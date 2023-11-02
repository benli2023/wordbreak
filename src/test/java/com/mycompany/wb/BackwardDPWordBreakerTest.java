package com.mycompany.wb;

import com.mycompnay.wb.BackwardDPWordBreaker;
import com.mycompnay.wb.Dictionary;
import com.mycompnay.wb.WordBreaker;

public class BackwardDPWordBreakerTest extends AbstractWordBreakerTest {

  @Override
  protected WordBreaker getWordBreaker(Dictionary dictionary) {
    return new BackwardDPWordBreaker(dictionary);
  }
}
