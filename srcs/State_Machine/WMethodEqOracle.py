from itertools import product
from operator import le
from random import shuffle, choice, randint
import random
import re
import sys
import os
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../../")
sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../libs/")
sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../libs/boofuzz/")

from aalpy.base.Oracle import Oracle
from aalpy.base.SUL import SUL
from Ble_state_check.srcs.State_Machine.Cache import CacheTree


class WMethodEqOracle(Oracle):
    """
    Equivalence oracle based on characterization set/ W-set. From 'Tsun S. Chow.  Testing software design modeled by
    finite-state machines'.

    """
    def __init__(self, alphabet: list, sul: SUL, max_number_of_states, shuffle_test_set=True,tested_letters_file= None,out_put_path = None,callback = None):
        """
        Args:

            alphabet: input alphabet
            sul: system under learning
            max_number_of_states: maximum number of states in the automaton
            shuffle_test_set: if True, test cases will be shuffled

        """

        super().__init__(alphabet, sul)
        self.m = max_number_of_states
        self.shuffle = shuffle_test_set
        self.cache = CacheTree()
        self.tested_letters_file = tested_letters_file

        self.tested_letters = []
        self.output = out_put_path
        self.block_callback = callback




    def find_cex(self, hypothesis):

        self.check_file()
        

        # hypothesis.characterization_set = [('pairing_request_pkt','pairing_confirm_pkt','pairing_random_pkt',), ('ll_enc_req_pkt','ll_start_enc_req_pkt',), ('ll_pause_enc_req_pkt',)]

        if not hypothesis.characterization_set:
            hypothesis.characterization_set = hypothesis.compute_characterization_set()
        print(hypothesis.characterization_set)
        # return
        hypothesis.characterization_set.remove(('pairing_random_pkt',))

        hypothesis.characterization_set.remove(('ll_feature_req_pkt',))
        if ('pairing_public_key_pkt',) in hypothesis.characterization_set:
            hypothesis.characterization_set.remove(('pairing_public_key_pkt',))
            self.alphabet.remove('pairing_confirm_pkt')
            
        hypothesis.characterization_set.remove(('ll_start_enc_rsp_pkt',))
        if ('ll_length_req_pkt',) in hypothesis.characterization_set:
            hypothesis.characterization_set.remove(('ll_length_req_pkt',))
        if ('ll_version_ind_pkt',) in hypothesis.characterization_set:
            hypothesis.characterization_set.remove(('ll_version_ind_pkt',))
        


        # covers every transition of the specification at least once.
        transition_cover = [state.prefix + (letter,) for state in hypothesis.states for letter in self.alphabet]
        
        for transition in transition_cover:
            if len(transition) < 2:
                transition_cover.remove(transition)
                print(transition)
        middle = []
        inp_seq = []
        # print("中间长度")
        
        # for i in range(self.m + 1 - len(hypothesis.states)):
        #     print(i)
        middle.extend(list(product(self.alphabet, repeat=1)))

        # print("中间长度")
        # print(transition_cover)
        
        seq_list = list(product(transition_cover, middle, hypothesis.characterization_set))
        for seq in seq_list:
            seq_trple = tuple([i for sub in seq for i in sub])
            if len(seq_trple) <4:
                continue
            else:   
                inp_seq.append(seq_trple)

        # print("总长度")
        # # print(len(inp_seq))
        random.shuffle(inp_seq)
        # seq = ('ll_version_ind_pkt', 'pairing_request_pkt', 'pairing_confirm_pkt', 'pairing_random_pkt')
        # if self.cache.in_cache(seq):
        #     print("已经测试过")

        for seq in inp_seq:
            print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
            if not self.cache.in_cache(seq): 
                self.reset_hyp_and_sul(hypothesis)
                outputs = []
                input_output = []
                
                for ind, letter in enumerate(seq):
                    # out_hyp = hypothesis.step(letter)
                    # print(letter)
                    out_sul = self.sul.step(letter)
                    self.num_steps += 1
                    input_output.append("("+letter+"|"+out_sul+")")
                    outputs.append(out_sul)
                    # if out_hyp != out_sul:
                    #     self.sul.post()
                    #     return inp_seq[:ind + 1]
                    if self.block_callback:
                        callback_result = self.block_callback(seq, input_output)
                        if callback_result:
                            seq = ("block_sequence",) + seq

                            
                            break

                self.write_to_file(seq,input_output)
                
                self.cache.add_to_cache(seq, outputs)
            else:
                print("已经测试过")
                # print(seq)
                # print(self.cache.in_cache(seq))
                # print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
        
        return None

    def is_subsequence(self,sub, main):
        """
        检查元组 sub 是否是元组 main 的子序列

        Args:
            sub (tuple): 子序列
            main (tuple): 主序列

        Returns:
            bool: 如果 sub 是 main 的子序列，则返回 True，否则返回 False
        """
        sub_len = len(sub)
        main_len = len(main)
        
        # 如果子序列长度大于主序列长度，则不可能是子序列
        if sub_len > main_len:
            return False
        for i in range(main_len - sub_len + 1):
            if sub == main[i:i + sub_len]:
                # print(main[i:i + sub_len])
                return True
        
        # 检查子序列是否存在于主序列中
        return False
    def write_to_file(self, seq, input_output):
        with open(self.output, 'a') as f:
            f.write(",".join(input_output)+ "\n")
        if self.tested_letters_file:
            with open(self.tested_letters_file, 'a') as f:
                f.write(",".join(seq) + "\n")

    # 检查是否在测试tested_letters 中，或者为已经测试过的序列的子序列
    def check_tested(self, seq, all_seq):
        # 如果没有测试过的序列
        # if len(self.tested_letters)==0:
        #     pass
        for tested_seq in all_seq:
            if self.is_subsequence(seq, tested_seq):
                return True
        return False

        # for tested_seq in self.tested_letters:
        #     if self.is_subsequence(seq, tested_seq.split(",")):
        #         return True
        #     else:
        #         self.tested_letters.append(seq)
        # return False
    # 判断文件是否存在没有创建一个
    def check_file(self):
        if self.tested_letters_file:
            if not os.path.exists(self.tested_letters_file):
                open(self.tested_letters_file, 'w').close()
            with open(self.tested_letters_file, 'r') as f:
                read_result = f.read().splitlines()
            i = 0
            for line in read_result:

                result_tuple = tuple(line.split(','))
                # print(result_tuple)
                if not self.cache.in_cache(result_tuple):
                    self.cache.add_to_cache(result_tuple)
                    i += 1
        
            

            
                

