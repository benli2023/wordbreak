package com.mycompnay.wb;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;


/**
 * Dynamic programming implementation
 */
public class ForwardDPWordBreaker implements WordBreaker {

  private Dictionary dictionary;


  public ForwardDPWordBreaker(Dictionary dictionary) {
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
      String prefix = word.substring(0, i);
      if (dictionary.contain(prefix)) {
        Set<String> subfixSet = interalBreak(word.substring(i), wordBreakMap);
        Iterator<String> it = subfixSet.iterator();
        while (it.hasNext()) {
          String subfix = it.next();
          result.add(prefix + " " + subfix);
        }
      }
    }
    wordBreakMap.put(word, result);
    return result;
  }

}
