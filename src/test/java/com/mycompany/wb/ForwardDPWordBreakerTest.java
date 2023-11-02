package com.mycompany.wb;

import com.mycompnay.wb.ForwardDPWordBreaker;
import com.mycompnay.wb.Dictionary;
import com.mycompnay.wb.WordBreaker;

public class ForwardDPWordBreakerTest extends AbstractWordBreakerTest {


  @Override
  protected WordBreaker getWordBreaker(Dictionary dictionary) {
    return new ForwardDPWordBreaker(dictionary);
  }
}
