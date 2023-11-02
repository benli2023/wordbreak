package com.mycompany.wb;

import com.mycompnay.wb.Dictionary;
import com.mycompnay.wb.HashDictionary;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class HashDictionaryTest {

  Dictionary dictionary;

  @Before
  public void setUp() {
    String temp_dictionary[] = {"mobile", "samsung", "sam", "sung", "man", "mango", "icecream", "and", "go", "i", "like", "ice", "cream"};
    dictionary = new HashDictionary(temp_dictionary);
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
