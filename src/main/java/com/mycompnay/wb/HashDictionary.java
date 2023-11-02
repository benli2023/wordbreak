package com.mycompnay.wb;

import java.util.HashSet;
import java.util.Set;

/**
 * HASH SET implementation for dictionary
 */
public class HashDictionary implements Dictionary {

  private Set<String> wordSet = new HashSet<>();

  public HashDictionary(String[] dict) {
    for (String d : dict) {
      wordSet.add(d);
    }
  }

  @Override
  public boolean contain(String word) {
    return wordSet.contains(word);
  }
}
