package com.mycompany.wb;

import com.mycompnay.wb.BacktrackingWordBreaker;
import com.mycompnay.wb.Dictionary;
import com.mycompnay.wb.WordBreaker;

public class BacktrackingWordBreakerTest extends AbstractWordBreakerTest {


  @Override
  protected WordBreaker getWordBreaker(Dictionary dictionary) {
    return new BacktrackingWordBreaker(dictionary);
  }
}
