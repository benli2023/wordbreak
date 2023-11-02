package com.mycompany.wb;

import com.mycompnay.wb.Dictionary;
import com.mycompnay.wb.TrieNodeDictionary;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class TrieNodeDictionaryTest {


  Dictionary dictionary;

  @Before
  public void setUp() {
    String temp_dictionary[] = {"mobile", "samsung", "sam", "sung", "man", "mango", "icecream", "and", "go", "i", "like", "ice", "cream"};
    dictionary = new TrieNodeDictionary(temp_dictionary);
  }


  @Test
  public void checkExist() {
    Assert.assertTrue(dictionary.contain("mobile"));
  }


  @Test
  public void checkNotExist() {
    Assert.assertFalse(dictionary.contain("ok"));
  }

}
