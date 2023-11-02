package com.mycompnay.wb;

public class TrieNodeDictionary implements Dictionary {


  TrieNode root;

  public TrieNodeDictionary(String[] dict) {
    this.root = new TrieNode();
    for (String d : dict) {
      insert(d);
    }
  }

  @Override
  public boolean contain(String word) {
    return search(word);
  }


  void insert(String key) {
    TrieNode pNode = root;
    for (int i = 0; i < key.length(); i++) {
      int index = key.charAt(i) - 'a';
      if (pNode.getChild(index) == null) {
        pNode.setChild(index, new TrieNode());
      }
      pNode = pNode.getChild(index);
    }
    // mark last node as leaf
    pNode.setEndOfWord(true);
  }


  boolean search(String key) {
    TrieNode pNode = root;
    for (int i = 0; i < key.length(); i++) {
      int index = key.charAt(i) - 'a';
      if (pNode.getChild(index) == null) {
        return false;
      }
      pNode = pNode.getChild(index);
    }
    return pNode != null && pNode.isEndOfWord();
  }


}
