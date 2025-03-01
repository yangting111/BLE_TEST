from re import T
import time
from typing import Union
from venv import logger

from aalpy.automata import Dfa, DfaState, MealyState, MealyMachine, MooreState, MooreMachine, \
    Sevpa, SevpaState, SevpaAlphabet
from aalpy.base import Oracle, SUL
from aalpy.utils.HelperFunctions import print_learning_info, visualize_classification_tree


from Ble_state_check.srcs.Send_Packet import constant
from .ClassificationTree import ClassificationTree
from .CounterExampleProcessing import counterexample_successfully_processed
from ...base.SUL import CacheSUL
import logging

print_options = [0, 1, 2, 3]
counterexample_processing_strategy = ['rs', 'linear_fwd', 'linear_bwd', 'exponential_fwd', 'exponential_bwd']
automaton_class = {'dfa': Dfa, 'mealy': MealyMachine, 'moore': MooreMachine, 'vpa': Sevpa}





def run_KV(alphabet: Union[list, SevpaAlphabet], sul: SUL, eq_oracle: Oracle, automaton_type, logger_handle, cex_processing='rs',
           max_learning_rounds=None, hypothesis=None, return_data=False, print_level=2):
    """
    Executes the KV algorithm.

    Args:

        alphabet: input alphabet

        sul: system under learning

        eq_oracle: equivalence oracle

        automaton_type: type of automaton to be learned. One of 'dfa', 'mealy', 'moore', 'vpa'

        cex_processing: Counterexample processing strategy. Either 'rs' (Riverst-Schapire), 'longest_prefix'.
            (Default value = 'rs'), 'longest_prefix', 'linear_fwd', 'linear_bwd', 'exponential_fwd', 'exponential_bwd'

        max_learning_rounds: number of learning rounds after which learning will terminate (Default value = None)

        cache_and_non_det_check: Use caching and non-determinism checks (Default value = True)

        return_data: if True, a map containing all information(runtime/#queries/#steps) will be returned
            (Default value = False)

        print_level: 0 - None, 1 - just results, 2 - current round and hypothesis size, 3 - educational/debug
            (Default value = 2)

    Returns:

        automaton of type automaton_type (dict containing all information about learning if 'return_data' is True)

    """

    assert print_level in print_options
    assert cex_processing in counterexample_processing_strategy
    assert automaton_type in [*automaton_class]
    assert automaton_type != 'vpa' and isinstance(alphabet, list) or isinstance(alphabet, SevpaAlphabet)

    start_time = time.time()
    eq_query_time = 0
    learning_rounds = 0
    logger = logging.getLogger(logger_handle)
    global switch
   
    hypothesis = hypothesis
   


    # Perform an equivalence query on this automaton
    eq_query_start = time.time()
    cex = eq_oracle.find_cex(hypothesis)

    eq_query_time += time.time() - eq_query_start
    

    classification_tree = None

    if cex is not None:
        cex = tuple(cex)

        # initialise the classification tree to have a root
        # labeled with the empty word as the distinguishing string
        # and two leaves labeled with access strings cex and empty word
        classification_tree = ClassificationTree(alphabet=alphabet, sul=sul, automaton_type=automaton_type, cex=cex)

        while not sul.exit_flag:
            learning_rounds += 1

            logger.info(f'Learning round {learning_rounds}')
            
            if max_learning_rounds and learning_rounds - 1 == max_learning_rounds:
                break
            logger.info(f"entering update_hypothesis")
            hypothesis = classification_tree.update_hypothesis()

            if print_level == 2:
                print(f'\rHypothesis {learning_rounds}: {hypothesis.size} states.', end="")

            if print_level == 3:
                # would be nice to have an option to print classification tree
                print(f'Hypothesis {learning_rounds}: {hypothesis.size} states.')
            
            logger.info(f'Hypothesis {learning_rounds}: {hypothesis.size} states.')

            if counterexample_successfully_processed(sul, cex, hypothesis):
                # Perform an equivalence query on this automaton
                eq_query_start = time.time()
                cex = eq_oracle.find_cex(hypothesis)
                eq_query_time += time.time() - eq_query_start
                logger.info(f"eq_query_start: {eq_query_start}, eq_query_time: {eq_query_time}")

                if cex is None:
                    break

                else:
                    cex = tuple(cex)

                if print_level == 3:
                    print('Counterexample', cex)
                logger.info(f'Counterexample {cex}')    

            classification_tree.process_counterexample(cex, hypothesis, cex_processing)

    if automaton_type == 'vpa':
        hypothesis.delete_state(hypothesis.get_error_state())

    total_time = round(time.time() - start_time, 2)
    eq_query_time = round(eq_query_time, 2)
    learning_time = round(total_time - eq_query_time, 2)

    info = {
        'learning_rounds': learning_rounds,
        'automaton_size': hypothesis.size,
        'queries_learning': sul.num_queries,
        'steps_learning': sul.num_steps,
        'queries_eq_oracle': eq_oracle.num_queries,
        'steps_eq_oracle': eq_oracle.num_steps,
        'learning_time': learning_time,
        'eq_oracle_time': eq_query_time,
        'total_time': total_time,
        'cache_saved': sul.num_cached_queries,
    }

    if print_level > 0:
        if print_level == 2:
            print("")
        print_learning_info(info)

        if print_level == 3 and classification_tree:
            print('Visualization of classification tree saved to classification_tree.pdf')
            visualize_classification_tree(classification_tree.root)

    if return_data:
        return hypothesis, info

    return hypothesis
