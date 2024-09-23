<template>
  <div
    :theme="theme"
    class="code-editor"
    :class="{
      'hide-header': !header,
      scroll: scroll,
      'read-only': readOnly,
      wrap: wrap,
    }"
    :style="{
      width: width,
      height: height,
      zIndex: zIndex,
      maxWidth: maxWidth,
      minWidth: minWidth,
      maxHeight: maxHeight,
      minHeight: minHeight,
    }"
  >
    <div class="hljs" :style="{ borderRadius: borderRadius }">
      <div
        class="header"
        :class="{ border: showLineNums }"
        v-if="header"
        :style="{ borderRadius: borderRadius + ' ' + borderRadius + ' 0 0' }"
      >
        <div class="headertext" v-if="displayHeaderText">{{ headerText }}</div>
        <Dropdown
          v-if="displayLanguage"
          :width="langListWidth"
          :title="languageTitle"
          :disabled="languages.length <= 1"
          :defaultDisplay="langListDisplay"
        >
          <ul class="lang-list hljs" :style="{ height: langListHeight }">
            <li v-for="(lang, index) in languages" :key="index" @click="changeLang(lang)">
              {{ lang[1] ? lang[1] : lang[0] }}
            </li>
          </ul>
        </Dropdown>
        <div class="upbtn-bar">
          <DownloadCode class="download-code" @handle="download" v-if="downloadCode"></DownloadCode>
          <ClearCode class="clear-code" @handle="clear" v-if="clearCode"></ClearCode>
          <CopyCode class="copy-code" @handle="copy" v-if="copyCode"></CopyCode>
        </div>
      </div>
      <div
        class="code-area"
        :style="{
          borderRadius: header ? '0 0 ' + borderRadius + ' ' + borderRadius : borderRadius,
        }"
      >
        <div
          v-if="showLineNums"
          ref="lineNums"
          class="line-nums hljs"
          :style="{
            fontSize: fontSize,
            paddingTop: header ? '10px' : padding,
            paddingBottom: padding,
            top: top + 'px',
          }"
        >
          <div>1</div>
          <div v-for="num in lineNum">
            <span :class="{ prevent: num + 1 > CodeLineNum }">{{ num + 1 }}</span>
          </div>
          <div>&nbsp;</div>
        </div>
        <textarea
          :readOnly="readOnly || ansiMode"
          :style="{
            fontSize: fontSize,
            padding: !header
              ? padding
              : lineNums
              ? ['10px', padding, padding].join(' ')
              : ['0', padding, padding].join(' '),
            marginLeft: showLineNums ? lineNumsWidth + 'px' : '0',
            width: showLineNums ? 'calc(100% - ' + lineNumsWidth + 'px)' : '100%',
            zIndex: '11',
            overflow: ansiMode ? 'hidden' : '',
          }"
          :placeholder="placeholder"
          ref="textarea"
          :autofocus="autofocus"
          spellcheck="false"
          @keydown.tab.stop="tab"
          @scroll="calcScrollDistance"
          :value="plainValue"
          @input="updateValue"
        ></textarea>
        <pre
          :style="{
            paddingRight: scrollBarWidth + 'px',
            paddingBottom: scrollBarHeight + 'px',
            marginLeft: showLineNums ? lineNumsWidth + 'px' : '0',
            width: showLineNums ? 'calc(100% - ' + lineNumsWidth + 'px)' : '100%',
            zIndex: ansiMode ? '12' : '10',
          }"
        >
        <code
          ref="code"
          v-if="!ansiMode"
          v-highlight="contentValue+'\n'"
          :class="languageClass"
          :style="{
            top: top + 'px',
            left: left + 'px',
            fontSize: fontSize,
            padding: !header
              ? padding
              : lineNums
              ? ['10px', padding, padding].join(' ')
              : ['0', padding, padding].join(' ')
          }">
        </code>
        <code
          ref="code"
          v-if="ansiMode"
          :class="languageClass"
          :style="{
            top: top + 'px',
            left: left + 'px',
            fontSize: fontSize,
            padding: !header
              ? padding
              : lineNums
              ? ['10px', padding, padding].join(' ')
              : ['0', padding, padding].join(' '),
            overflow: 'auto'
          }"
          v-html="ansiHtmlValue"
          :contenteditable="!readOnly"
          @focus="this.noUpdateCodeHtml = false"
          @input="updateValue"
           ></code>
      </pre>
      </div>
    </div>
  </div>
</template>

<script>
import hljs from "highlight.js";
import Convert from "@/scripts/ansihtml";
import Dropdown from "simple-code-editor/Dropdown.vue";
import DownloadCode from "./CodeEditor/DownloadCode.vue";
import ClearCode from "./CodeEditor/CopyCode.vue";
import CopyCode from "./CodeEditor/CopyCode.vue";
import "simple-code-editor/themes/themes-base16.css";
import "simple-code-editor/themes/themes.css";

const ansi = new Convert({
  fg: "#FFF",
  bg: "#000",
  newline: false,
  escapeXML: false,
  stream: false,
});

const escapeHtml = (s) => {
  return s.replace(/[&<>"' \r\n]/g, function (tag) {
    const lookup = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&apos;",
      " ": "&nbsp;",
      "\r": "",
      "\n": "<br/>",
    };
    return lookup[tag] || tag;
  });
};

const unescapeHtml = (s) => {
  return s.replace(/&amp;|&lt;|&gt;|&quot;|&apos;|&nbsp;|<br\/>/g, function (tag) {
    const lookup = {
      "&amp;": "&",
      "&lt;": "<",
      "&gt;": ">",
      "&quot;": '"',
      "&apos;": "'",
      "&nbsp;": " ",
      "<br/>": "\n",
    };
    return lookup[tag] || tag;
  });
};

export default {
  components: {
    Dropdown,
    CopyCode,
    ClearCode,
    DownloadCode,
  },
  name: "code-editor",
  props: {
    lineNums: {
      type: Boolean,
      default: false,
    },
    modelValue: {
      type: String,
    },
    value: {
      type: String,
    },
    theme: {
      type: String,
      default: "github-dark",
    },
    tabSpaces: {
      type: Number,
      default: 2,
    },
    wrap: {
      type: Boolean,
      default: false,
    },
    ansiMode: {
      type: Boolean,
      default: false,
    },
    readOnly: {
      type: Boolean,
      default: false,
    },
    placeholder: {
      type: String,
      default: "",
    },
    autofocus: {
      type: Boolean,
      default: false,
    },
    header: {
      type: Boolean,
      default: true,
    },
    headerText: {
      type: String,
      default: "",
    },
    displayHeaderText: {
      type: Boolean,
      default: false,
    },
    width: {
      type: String,
      default: "540px",
    },
    height: {
      type: String,
      default: "auto",
    },
    maxWidth: {
      type: String,
    },
    minWidth: {
      type: String,
    },
    maxHeight: {
      type: String,
    },
    minHeight: {
      type: String,
    },
    borderRadius: {
      type: String,
      default: "12px",
    },
    languages: {
      type: Array,
      default: function () {
        return [["javascript", "JS", "code.js"]];
      },
    },
    langListWidth: {
      type: String,
      default: "110px",
    },
    langListHeight: {
      type: String,
      default: "auto",
    },
    langListDisplay: {
      type: Boolean,
      default: false,
    },
    displayLanguage: {
      type: Boolean,
      default: true,
    },
    copyCode: {
      type: Boolean,
      default: true,
    },
    clearCode: {
      type: Boolean,
      default: true,
    },
    downloadCode: {
      type: Boolean,
      default: true,
    },
    zIndex: {
      type: String,
      default: "0",
    },
    fontSize: {
      type: String,
      default: "17px",
    },
    padding: {
      type: String,
      default: "20px",
    },
  },
  directives: {
    highlight: {
      mounted(el, binding) {
        el.textContent = binding.value;
        hljs.highlightElement(el);
      },
      updated(el, binding) {
        if (el.scrolling) {
          el.scrolling = false;
        } else {
          el.textContent = binding.value;
          hljs.highlightElement(el);
        }
      },
    },
  },
  data() {
    return {
      noUpdateCodeHtml: false,
      scrollBarWidth: 0,
      scrollBarHeight: 0,
      top: 0,
      left: 0,
      languageClass: "hljs language-" + this.languages[0][0],
      languageTitle: this.languages[0][1] ? this.languages[0][1] : this.languages[0][0],
      languageFilename: this.languages[0][2] ? this.languages[0][2] : "code.txt",
      content: this.value,
      cursorPosition: 0,
      insertTab: false,
      CodeLineNum: 1,
      lineNum: 0,
      lineNumsWidth: 0,
      scrolling: false,
      textareaHeight: 0,
      showLineNums: this.wrap ? false : this.lineNums,
    };
  },
  computed: {
    tabWidth() {
      let result = "";
      for (let i = 0; i < this.tabSpaces; i++) {
        result += " ";
      }
      return result;
    },
    contentValue() {
      return (this.modelValue == undefined ? this.content : this.modelValue) || "";
    },
    ansiHtmlValue() {
      if (this.ansiMode) {
        return this.ansi2html(this.contentValue);
      } else {
        return this.contentValue;
      }
    },
    plainValue() {
      if (this.ansiMode) {
        return unescapeHtml(this.ansiHtmlValue).replace(/<[^>]+>/g, "");
      } else {
        return this.contentValue;
      }
    },
    scroll() {
      return this.height == "auto" ? false : true;
    },
  },
  methods: {
    ansi2html(str) {
      return ansi
        .toHtml(escapeHtml(str))
        .replace(/(<\/span>)([^<]+)(<span>)/g, "$1<span>$2</span>$3")
        .replace(/^([^<]+)/g, "<span>$1</span>")
        .replace(/([^>]+)$/g, "<span>$1</span>")
        .replace(/<span><\/span>$/g, "");
    },
    updateValue(e) {
      if (this.ansiMode) {
        if (this.modelValue == undefined) {
          this.content = ansi.toAnsi(unescapeHtml(e.target.innerHTML));
        } else {
          this.$emit("update:modelValue", ansi.toAnsi(unescapeHtml(e.target.innerHTML)));
        }
      } else {
        if (this.modelValue == undefined) {
          this.content = e.target.value;
        } else {
          this.$emit("update:modelValue", e.target.value);
        }
      }
    },
    changeLang(lang) {
      this.languageTitle = lang[1] ? lang[1] : lang[0];
      this.languageClass = "language-" + lang[0];
      this.languageFilename = lang[2] ? lang[2] : "code.txt";
      this.$emit("lang", lang[0]);
    },
    setLanguage(displayLangName) {
      for (let lang of this.languages) {
        if (lang[1] === displayLangName) {
          this.changeLang(lang);
          return;
        }
      }
    },
    tab(e) {
      if (document.execCommand("insertText")) {
        e.preventDefault();
        document.execCommand("insertText", false, this.tabWidth);
      } else if (!this.ansiMode) {
        e.preventDefault();
        const cursorPosition = this.$refs.textarea.selectionStart;
        this.content =
          this.content.substring(0, cursorPosition) +
          this.tabWidth +
          this.content.substring(cursorPosition);
        this.cursorPosition = cursorPosition + this.tabWidth.length;
        this.insertTab = true;
      }
    },
    calcScrollDistance(e) {
      this.$refs.code.scrolling = true;
      this.scrolling = true;
      this.top = -e.target.scrollTop;
      this.left = -e.target.scrollLeft;
    },
    resizer() {
      // textareaResizer
      const textareaResizer = new ResizeObserver((entries) => {
        this.scrollBarWidth = entries[0].target.offsetWidth - entries[0].target.clientWidth;
        this.scrollBarHeight = entries[0].target.offsetHeight - entries[0].target.clientHeight;
        this.textareaHeight = entries[0].target.offsetHeight;
      });
      textareaResizer.observe(this.$refs.textarea);
      // lineNumsResizer
      const lineNumsResizer = new ResizeObserver((entries) => {
        this.lineNumsWidth = entries[0].target.offsetWidth;
      });
      if (this.$refs.lineNums) {
        lineNumsResizer.observe(this.$refs.lineNums);
      }
    },
    copy() {
      const copyReact = (e) => {
        e.clipboardData.setData("text/plain", this.$refs.textarea.value);
        e.preventDefault();
      };
      document.addEventListener("copy", copyReact);
      if (document.execCommand("copy")) {
        document.removeEventListener("copy", copyReact);
      } else {
        document.removeEventListener("copy", copyReact);
        navigator.clipboard.writeText(this.$refs.textarea.value);
      }
    },
    clear() {
      this.modelValue == undefined ? (this.content = "") : this.$emit("update:modelValue", "");
    },
    download() {
      const blob = new Blob([this.$refs.textarea.value], {
        type: "text/plain",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = this.languageFilename;
      a.click();
      URL.revokeObjectURL(url);
    },
    getCodeLineNum() {
      // lineNum
      const str = this.$refs.textarea.value;
      let lineNum = 1;
      let position = str.indexOf("\n");
      while (position !== -1) {
        lineNum++;
        position = str.indexOf("\n", position + 1);
      }
      this.CodeLineNum = lineNum;
      return lineNum;
    },
    getLineNum() {
      // lineNum
      let lineNum = this.CodeLineNum - 1;
      // heightNum
      const singleLineHeight = this.$refs.lineNums.firstChild.offsetHeight;
      const heightNum = parseInt(this.textareaHeight / singleLineHeight) - 1;
      // displayed lineNum
      this.lineNum = this.height == "auto" ? lineNum : lineNum > heightNum ? lineNum : heightNum;
    },
  },
  expose: ["setLanguage"],
  mounted() {
    this.$emit("lang", this.languages[0][0]);
    this.$emit("content", this.content);
    this.$emit("textarea", this.$refs.textarea);
    this.resizer();
  },
  updated() {
    this.getCodeLineNum();
    if (this.insertTab) {
      this.$refs.textarea.setSelectionRange(this.cursorPosition, this.cursorPosition);
      this.insertTab = false;
    }
    if (this.lineNums) {
      if (this.scrolling) {
        this.scrolling = false;
      } else {
        this.getLineNum();
      }
    }
  },
};
</script>

<style lang="scss">
.code-editor {
  position: relative;
}
.code-editor > div {
  width: 100%;
  height: 100%;
}
/* header */
.code-editor .header {
  box-sizing: border-box;
  position: relative;
  z-index: 1;
  height: 34px;
  display: flex;
  align-items: center;
  flex-direction: row;
  flex-wrap: nowrap;
  padding-left: 0.5rem;
  & > .headertext {
    position: relative;
    width: min-content;
    font-size: 0.93rem;
    font-weight: bold;
    margin: 0.3rem 0.5rem;
    opacity: 0.8;
    font-family: Chinese Quote, Segoe UI, Roboto, PingFang SC, Hiragino Sans GB, Microsoft YaHei,
      Helvetica Neue, Helvetica, Arial, sans-serif, Apple Color Emoji;
  }
  & > .upbtn-bar {
    display: flex;
    align-items: center;
    flex-direction: row;
    flex-wrap: nowrap;
    margin-left: auto;
    margin-right: 0.3rem;
    & > * {
      margin: 0.3rem;
    }
  }
  & > .dropdown {
    position: relative;
    width: min-content;
    margin: 0.3rem 0.5rem;
    .list {
      font-family: PingFang SC, Hiragino Sans GB, Microsoft YaHei, Helvetica Neue, Helvetica, Arial,
        sans-serif, Segoe UI;
    }
  }
}
/* code-area */
.code-editor .code-area {
  position: relative;
  z-index: 0;
  text-align: left;
  overflow: hidden;
  & *::selection {
    background-color: rgba(61, 170, 194, 0.25);
  }
  [contenteditable],
  [contenteditable]:active,
  [contenteditable]:focus,
  [contenteditable]:focus-visible {
    border: 1px solid transparent;
    outline: 1px solid transparent;
  }
  & > textarea,
  & > pre > code {
    padding-left: 16px !important;
  }
}
/* font style */
.code-editor .code-area > textarea,
.code-editor .code-area > pre > code,
.code-editor .line-nums > div {
  font-family: Consolas, Monaco, monospace;
  line-height: 1.5;
}
.code-editor .code-area > textarea:hover,
.code-editor .code-area > textarea:focus-visible {
  outline: none;
}
.code-editor .code-area > textarea {
  position: absolute;
  z-index: 1;
  top: 0;
  left: 0;
  box-sizing: border-box;
  caret-color: rgb(127, 127, 127);
  color: transparent;
  white-space: pre;
  word-wrap: normal;
  border: 0;
  width: 100%;
  height: 100%;
  background: none;
  resize: none;
}
.code-editor .code-area > pre {
  box-sizing: border-box;
  position: relative;
  z-index: 0;
  overflow: hidden;
  font-size: 0;
  margin: 0;
}
.code-editor .code-area > pre > code {
  background: none;
  display: block;
  position: relative;
  overflow-x: visible !important;
  border-radius: 0;
  box-sizing: border-box;
  margin: 0;
}
/* wrap code */
.code-editor.wrap .code-area > textarea,
.code-editor.wrap .code-area > pre > code {
  white-space: pre-wrap;
  word-wrap: break-word;
}
/* hide-header */
.code-editor.hide-header.scroll .code-area {
  height: 100%;
}
/* scroll */
.code-editor.scroll .code-area {
  height: calc(100% - 34px);
  & > pre > code,
  & > textarea {
    cursor: text;
    font-family: "MesloLGS Nerd Font Mono", SFMono-Regular, "SF Mono", "Cascadia Mono", Menlo,
      Consolas, "JetBrains Mono", "Liberation Mono", "Courier New", Courier, monospace;
    $scrollbar-width: 8px;
    &::-webkit-scrollbar {
      width: $scrollbar-width;
      height: $scrollbar-width;
    }

    &::-webkit-scrollbar-track {
      background-color: transparent;
      width: $scrollbar-width;
      height: $scrollbar-width;
    }

    &::-webkit-scrollbar-thumb {
      background-color: #3e3f41;
    }

    &::-webkit-scrollbar-thumb:hover {
      background-color: #5b5c60;
      cursor: grab;
    }

    &::-webkit-scrollbar-thumb:active {
      background-color: #5b5c60;
      cursor: grabbing;
    }

    &::-webkit-scrollbar-corner {
      background-color: transparent;
    }

    &::-webkit-scrollbar-button {
      height: 0;
    }
  }
}
.code-editor.scroll .code-area > pre {
  width: 100%;
  height: 100%;
  overflow: hidden;
}
/* dropdown */
.code-editor .list {
  -webkit-user-select: none;
  user-select: none;
  height: 100%;
  font-family: sans-serif;
}
.code-editor .list > .lang-list {
  border-radius: 5px;
  box-sizing: border-box;
  overflow: auto;
  font-size: 13px;
  padding: 0;
  margin: 0;
  list-style: none;
  text-align: left;
}
.code-editor .list > .lang-list > li {
  font-size: 13px;
  transition: background 0.16s ease, color 0.16s ease;
  box-sizing: border-box;
  padding: 0 12px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  line-height: 30px;
}
.code-editor .list > .lang-list > li:first-child {
  padding-top: 5px;
}
.code-editor .list > .lang-list > li:last-child {
  padding-bottom: 5px;
}
.code-editor .list > .lang-list > li:hover {
  background: rgba(160, 160, 160, 0.4);
}
/* line-nums */
.code-editor .line-nums {
  min-width: 36px;
  text-align: right;
  box-sizing: border-box;
  position: absolute;
  left: 0;
  padding-right: 8px;
  padding-left: 8px;
  opacity: 0.3;
  user-select: none;
}
.code-editor .line-nums .prevent {
  pointer-events: none;
  user-select: none;
  opacity: 0;
}
.code-editor .line-nums::after {
  content: "";
  position: absolute;
  width: 100%;
  height: 100%;
  top: 0;
  left: 0;
  border-right: 1px solid currentColor;
  opacity: 0.5;
}
.code-editor .header.border::after {
  content: "";
  position: absolute;
  width: 100%;
  height: 1px;
  bottom: 0;
  left: 0;
  background: currentColor;
  opacity: 0.15;
}
</style>
