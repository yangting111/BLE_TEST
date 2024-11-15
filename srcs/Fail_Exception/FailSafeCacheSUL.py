from Ble_Test.srcs.Send_Packet import constant
from colorama import Fore
from aalpy.base import SUL
from Fail_Exception.CacheTree import CacheTree
from time import sleep
from Fail_Exception.Fail_Exception import NonDeterministicError, RepeatedNonDeterministicError
from Fail_Exception.FailSafeSUL import FailSafeSUL

###
# The code used in this file is copied from the SweynTooth project:
# https://github.com/DES-Lab/AALpy
#
# Following file/class has been copied:
# -- aalpy/base/SUL.py
#
# Adaptions to the existing code have been made:
# -- check for non-determinism
#
#
###

class FailSafeCacheSUL(SUL):
    """
    System under learning that keeps a multiset of all queries in memory.
    This multiset/cache is encoded as a tree.
    """
    def __init__(self, sul: FailSafeSUL):
        super().__init__()
        self.sul = sul
        self.cache = CacheTree(constant.NON_DET_CACHE_SIZE)
        self.non_det_query_counter = 0
        self.non_det_step_counter = 0

    def query(self, word):
        """
        Performs a membership query on the SUL if and only if `word` is not a prefix of any trace in the cache.
        Before the query, pre() method is called and after the query post()
        method is called. Each letter in the word (input in the input sequence) is executed using the step method.

        Args:

            word: membership query (word consisting of letters/inputs)

        Returns:

            list of outputs, where the i-th output corresponds to the output of the system after the i-th input

        """

        cached_query = self.cache.in_cache(word)
        if cached_query:
            self.num_cached_queries += 1
            return cached_query

        attempts = 0
        while attempts < constant.NON_DET_ERROR_ATTEMPTS:
            try:
                non_det_update = 0
                while non_det_update < constant.NON_DET_CACHE_SIZE:
                    try: 
                        # get outputs using default query method
                        
                        out = self.sul.query(word)
                        last_query = word
                        self.num_queries += 1
                        self.num_steps += self.sul.performed_steps_in_query
                        # add input/outputs to tree
                        self.cache.reset()
                        for i, o in zip(word, out):
                                self.cache.step_in_cache(i, o)
                                
                        non_det_update = constant.NON_DET_CACHE_SIZE
                            
                        return out
                    except NonDeterministicError:
                        continue
                    except ConnectionError as e:
                        print(Fore.RED + e.message)
                        print(Fore.RED + last_query)
                        self.sul.sul_restart()
                        continue   
                    except RepeatedNonDeterministicError as exp:
                        continue   

            except RepeatedNonDeterministicError as exp:
                    attempts += 1
                    print(exp)
                    print(Fore.RED + "Non-determinism in query execution detected.")
                    self.non_det_query_counter += 1
                    self.sul.post()
                    if attempts == constant.NON_DET_ERROR_ATTEMPTS:
                        raise


    def pre(self):
        """
        Reset the system under learning and current node in the cache tree.
        """
        self.cache.reset()
        self.sul.pre()

    def post(self):
        self.sul.post()

    def step(self, letter):
        """
        Executes an action on the system under learning, adds it to the cache and returns its result.

        Args:

           letter: Single input that is executed on the SUL.

        Returns:

           Output received after executing the input.

        """
        out = self.sul.step(letter)
        try:
            self.cache.step_in_cache(letter, out)
        except RepeatedNonDeterministicError:
            print(Fore.RED + "Non-determinism in step execution detected.")
            self.non_det_step_counter += 1
            raise
        
        return out
