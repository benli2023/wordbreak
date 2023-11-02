
## Dictionary 

Dictionary responsible  for checking a string whether considered to be a word. There are 2 
implementation :
- `HashDictionary`  lookup a word by using internal hash set
- `TrieNodeDictionary` lookup a word by using Trie Node tree.



## WordBreaker 

WordBreaker is designed to find all possible combination of words from input string.
There are 3 implementation:
- `BacktrackingWordBreaker`   using backtracking strategy,trying a prefix and check the subfix,if subfix not eligible and try next prefix. 
- `ForwardDPWordBreaker`  use internal cache to cache the result as there are may many overlap sub-problem.this implementation use forward direction.
- `BackwardDPWordBreaker`  use internal cache to cache the result as there are may many overlap sub-problem.this implementation use  backward direction.
