package com.mycompnay.wb;

public class TrieNode {

  private static final int ALPHABET_SIZE = 26;

  public TrieNode() {
    this.endOfWord = false;
    this.children = new TrieNode[ALPHABET_SIZE];
  }

  private boolean endOfWord;

  private TrieNode[] children;

  public boolean isEndOfWord() {
    return endOfWord;
  }

  public void setEndOfWord(boolean endOfWord) {
    this.endOfWord = endOfWord;
  }

  public TrieNode[] getChildren() {
    return children;
  }

  public TrieNode getChild(int index) {
    return children[index];
  }

  public void setChild(int index, TrieNode child) {
    children[index] = child;
  }


  public void setChildren(TrieNode[] children) {
    this.children = children;
  }
}
