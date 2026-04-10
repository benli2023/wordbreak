
## Dictionary 

Dictionary responsible  for checking a string whether considered to be a word. There are 2 
implementation :
- `HashDictionary`  lookup a word by using internal hash set
- `TrieNodeDictionary` lookup a word by using Trie Node tree.



## WordBreaker 

WordBreaker is designed to find all possible combination of words from input string.
There are 3 implementation:
- `BacktrackingWordBreaker`   using backtracking strategy,trying a prefix and check the subfix,if subfix not eligible and try next prefix. 
- `ForwardDPWordBreaker`  use internal cache to cache the result as there are may many overlap sub-problem.this implementation use forward direction.
- `BackwardDPWordBreaker`  use internal cache to cache the result as there are may many overlap sub-problem.this implementation use  backward direction.


在 VS Code 中直接使用 GitHub Copilot（无论是行内代码补全，还是通过 `Ctrl+I` 生成编辑性代码）时，因为代码是直接“注入”到编辑器里的，前面的剪贴板脚本确实用不上了。

针对这种**“Copilot 在 VS Code 内直接生成的代码没对齐到第 8 列”**的情况，你有以下几种绝佳的应对策略，按优雅程度从高到低排列：

### 方法一：终极防范 —— 给 Copilot 设定“全局规则”（强烈推荐）

VS Code 的 Copilot 现在支持**项目级自定义指令**。你可以告诉 Copilot 你的项目规矩，它以后在生成代码时会自动遵守。

**操作步骤：**
1. 在你的项目根目录下，新建一个文件夹 `.github`。
2. 在里面新建一个文件，命名为 `copilot-instructions.md`。
3. 在这个文件里写上针对 RPGLE 的强制规则：
   ```markdown
   # RPGLE Coding Standards
   When generating or editing RPGLE (.rpgle) code, you MUST STRICTLY follow these formatting rules:
   1. DO NOT use Fully Free-Format (`**FREE`).
   2. All operational code (dcl-s, dcl-f, logic) MUST start exactly at Column 8.
   3. Columns 1 to 7 MUST be filled with exactly 7 spaces.
   4. Maintain relative indentation for inner blocks (IF, DO), but the outermost block MUST start at Column 8.
   ```
*效果：以后 Copilot 在这个项目里无论是行内提示还是聊天框生成，都会“潜意识”地在前面加上 7 个空格。*

---

### 方法二：针对 Inline Chat (`Ctrl + I`) 的“后缀咒语”

如果你按 `Ctrl + I`（或者 `Cmd + I`）呼出 Copilot 的行内编辑框让它写代码，你可以利用 VS Code 的特性，把对齐要求做成一个简短的提示词后缀。

不要只写：`增加一个检查库存的逻辑`
**要写：** `增加一个检查库存的逻辑。前面加7个空格对齐到第8列`

Copilot 在直接往文件里插入代码时，如果明确收到“前缀空格”的指令，它通常能正确处理。

---

### 方法三：VS Code 快捷键“秒修”法（最实用）

如果 Copilot 已经生成了错位的代码（比如顶格到了第 1 列），不要一个一个去敲空格。利用 VS Code 的多行编辑功能，**2 秒钟**就能修好。

**步骤 1：为 RPGLE 设置专属 Tab 宽度（一次性设置）**
1. 在 VS Code 中打开任意 `.rpgle` 文件。
2. 按 `Ctrl + Shift + P` 打开命令面板，输入 `Preferences: Configure Language Specific Settings`。
3. 选择 `RPGLE`。
4. 在打开的 `settings.json` 中，添加以下配置：
   ```json
   "[rpgle]": {
       "editor.tabSize": 7,
       "editor.insertSpaces": true
   }
   ```

**步骤 2：生成后的秒修操作**
当 Copilot 生成完代码，你发现它顶格（或缩进不对）时：
1. **选中** Copilot 刚刚生成的那整块代码。
2. 按快捷键 **`Shift + Tab`** 狂按两三下（把所有代码强制向左推到第 1 列顶格）。
3. 按 **`Tab`** 键 **1 次**。
*效果：因为你设置了 Tab 宽为 7，代码会瞬间整体平移 7 个空格，精准落入第 8 列！同时保留了代码内部的 IF/ELSE 相对缩进。*

---

### 方法四：利用“列选择模式” (Column Selection)

如果 Copilot 生成的代码前面乱七八糟，有的在第 3 列，有的在第 5 列。你可以用 VS Code 程序员最爱的“多光标”：

1. 选中生成的代码块，按 `Shift + Tab` 全推到最左边（顶格）。
2. 按住 **`Shift + Alt`**，然后用鼠标在代码块的**第 1 列往下拖动**（或者用 `Ctrl+Shift+Alt+向下方向键`）。
   *此时你会发现每一行的行首都出现了一个闪烁的光标。*
3. 直接敲击键盘的**空格键 7 次**。
4. 按 `Esc` 退出多光标模式。

### 总结
*   **长久之计**：用 **方法一** `.github/copilot-instructions.md` 把规矩定死，让 AI 适应你。
*   **日常手速**：配置好 RPGLE 的 TabSize 为 7（**方法三**），生成不对直接选中文本 `Shift+Tab` 到底，再 `Tab` 一下，行云流水。




"请生成 RPGLE 自由格式代码。
注意：不使用 **FREE。由于 RPGLE 语法要求，所有有效的代码（包括 dcl-s, dcl-f 和计算逻辑）必须严格从第 8 列开始！
建议在每行代码前加上 7 个空格。请在代码块的第一行输出一个标尺帮助对齐：
.......8....+....2....+....3 "







