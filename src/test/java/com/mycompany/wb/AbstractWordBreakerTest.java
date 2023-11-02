package com.mycompany.wb;

import com.mycompnay.wb.Dictionary;
import com.mycompnay.wb.HashDictionary;
import com.mycompnay.wb.WordBreaker;
import java.util.Set;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public abstract class AbstractWordBreakerTest {

  WordBreaker wordBreaker;

  @Before
  public void setUp() {
    String temp_dictionary[] = {"mobile", "samsung", "sam", "sung", "man", "mango", "icecream", "and", "go", "i", "like", "ice", "cream"};
    Dictionary dictionary = new HashDictionary(temp_dictionary);
    wordBreaker = getWordBreaker(dictionary);
  }


  protected abstract WordBreaker getWordBreaker(Dictionary dictionary);

  @Test
  public void testWord() {
    Set<String> result = wordBreaker.breakWord("ilikemobile");
    String[] expected = new String[]{"i like mobile"};
    Assert.assertTrue(match(expected, result));
  }

  @Test
  public void testDoubleCombinedWord() {
    Set<String> result = wordBreaker.breakWord("ilikesamsung");
    String[] expected = new String[]{"i like samsung", "i like sam sung"};
    Assert.assertTrue(match(expected, result));
  }

  @Test
  public void testSingleCharacterWord() {
    Set<String> result = wordBreaker.breakWord("iiiiiiii");
    String[] expected = new String[]{"i i i i i i i i"};
    Assert.assertTrue(match(expected, result));
  }


  @Test
  public void testBlankString() {
    Set<String> result = wordBreaker.breakWord("");
    int length = result.size();
    Assert.assertTrue(length == 0);
  }


  @Test
  public void testSingleCharacterAndDoubleWord() {
    Set<String> result = wordBreaker.breakWord("ilikelikeimangoiii");
    String[] expected = new String[]{"i like like i man go i i i", "i like like i mango i i i"};
    Assert.assertTrue(match(expected, result));
  }

  @Test
  public void testTwoDoubleWord() {
    Set<String> result = wordBreaker.breakWord("samsungandmango");
    String[] expected = new String[]{"samsung and man go", "samsung and mango", "sam sung and mango", "sam sung and man go"};
    Assert.assertTrue(match(expected, result));
  }


  @Test
  public void testNotExistWord() {
    Set<String> result = wordBreaker.breakWord("samsungandmangok");
    int length = result.size();
    Assert.assertTrue(length == 0);
  }

  @Test
  public void testSample1() {
    Set<String> result = wordBreaker.breakWord("ilikesamsungmobile");
    String[] expected = new String[]{"i like sam sung mobile", "i like samsung mobile"};
    Assert.assertTrue(match(expected, result));
  }


  @Test
  public void testSample2() {
    Set<String> result = wordBreaker.breakWord("ilikeicecreamandmango");
    System.out.println(result);
    String[] expected = new String[]{"i like ice cream and man go", "i like ice cream and mango", "i like icecream and man go", "i like icecream and mango"};
    Assert.assertTrue(match(expected, result));
  }

  private boolean match(String[] expected, Set<String> actual) {
    for (String e : expected) {
      boolean exist = actual.contains(e);
      if (!exist) {
        return false;
      }
    }
    return true;
  }

}
