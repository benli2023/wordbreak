package com.mycompnay.wb;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;


/**
 * Dynamic programming backward implementation
 */
public class BackwardDPWordBreaker implements WordBreaker {

  private Dictionary dictionary;


  public BackwardDPWordBreaker(Dictionary dictionary) {
    this.dictionary = dictionary;
  }


  @Override
  public Set<String> breakWord(String word) {
    Map<String, Set<String>> wordBreakMap = new HashMap<>();
    return interalBreak(word, wordBreakMap);
  }


  private Set<String> interalBreak(String word, Map<String, Set<String>> wordBreakMap) {
    if (wordBreakMap.containsKey(word)) {
      return wordBreakMap.get(word);
    }
    Set<String> result = new HashSet<>();
    if(dictionary.contain(word)) {
      result.add(word);
    }
    int size = word.length();
    for (int i = 1; i < size; i++) {
      String subfix = word.substring(i);
      if (dictionary.contain(subfix)) {
        Set<String> prefixSet = interalBreak(word.substring(0,i), wordBreakMap);
        Iterator<String> it = prefixSet.iterator();
        while (it.hasNext()) {
          String prefix = it.next();
          result.add(prefix + " " + subfix);
        }
      }
    }
    wordBreakMap.put(word, result);
    return result;
  }

}
