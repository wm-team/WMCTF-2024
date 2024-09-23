<template>
  <div class="upbtn" @click="showMessage" @mouseout="resetMessage">
    <div class="tooltip">{{ message }}</div>
    <!-- https://www.iconfont.cn/collections/detail?spm=a313x.search_index.0.da5a778a4.6f763a81jBf9u2&cid=16071 -->
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 1024 1024"
      width="100%"
      height="100%"
      fill="currentColor"
    >
      <path
        d="M853.333333 981.333333h-384c-72.533333 0-128-55.466667-128-128v-384c0-72.533333 55.466667-128 128-128h384c72.533333 0 128 55.466667 128 128v384c0 72.533333-55.466667 128-128 128z m-384-554.666666c-25.6 0-42.666667 17.066667-42.666666 42.666666v384c0 25.6 17.066667 42.666667 42.666666 42.666667h384c25.6 0 42.666667-17.066667 42.666667-42.666667v-384c0-25.6-17.066667-42.666667-42.666667-42.666666h-384z"
      ></path>
      <path
        d="M213.333333 682.666667H170.666667c-72.533333 0-128-55.466667-128-128V170.666667c0-72.533333 55.466667-128 128-128h384c72.533333 0 128 55.466667 128 128v42.666666c0 25.6-17.066667 42.666667-42.666667 42.666667s-42.666667-17.066667-42.666667-42.666667V170.666667c0-25.6-17.066667-42.666667-42.666666-42.666667H170.666667c-25.6 0-42.666667 17.066667-42.666667 42.666667v384c0 25.6 17.066667 42.666667 42.666667 42.666666h42.666666c25.6 0 42.666667 17.066667 42.666667 42.666667s-17.066667 42.666667-42.666667 42.666667z"
      ></path>
    </svg>
  </div>
</template>

<script>
export default {
  name: "CopyCode",
  data() {
    return {
      message: "Copy",
      timeoutid: null,
    };
  },
  methods: {
    showMessage() {
      this.message = "Copied";
      this.$emit("handle");
      clearTimeout(this.timeoutid);
      this.timeoutid = setTimeout(() => {
        this.resetMessage();
      }, 800);
    },
    resetMessage() {
      clearTimeout(this.timeoutid);
      this.message = "Copy";
    },
  },
};
</script>

<style scoped lang="scss">
@import "@/styles/code-editor-upbtn.scss";
</style>
