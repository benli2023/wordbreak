package com.mycompnay.wb;

import java.util.HashSet;
import java.util.Set;


/**
 * backtracking implementation
 */
public class BacktrackingWordBreaker implements WordBreaker {


  private Dictionary dictionary;

  public BacktrackingWordBreaker(Dictionary dictionary) {
    this.dictionary = dictionary;
  }


  private void internalBreak(String word, String result, Set<String> resultSet) {
    int size = word.length();
    for (int i = 1; i <= size; i++) {
      String prefix = word.substring(0, i);
      if (dictionary.contain(prefix)) {
        if (i == size) {
          resultSet.add(result + prefix);
        } else {
          internalBreak(word.substring(i), result + prefix + " ", resultSet);
        }
      }
    }
  }


  @Override
  public Set<String> breakWord(String word) {
    Set<String> resultSet = new HashSet<>();
    internalBreak(word, "", resultSet);
    return resultSet;
  }
}
