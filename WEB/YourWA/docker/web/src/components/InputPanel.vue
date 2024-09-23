<script setup lang="ts">
import CodeEditor from "./CodeEditor.vue";

defineProps<{ gridClass: string }>();

const inputData = defineModel<string>({ default: "" });
</script>

<template>
  <el-card :class="gridClass">
    <code-editor
      :line-nums="true"
      :read-only="false"
      :languages="[['plaintext', 'Input', 'input.txt']]"
      :display-language="false"
      :display-header-text="true"
      header-text="INPUT"
      :header="true"
      :tab-space="4"
      :wrap="false"
      placeholder="Input"
      theme="vs2015"
      width="100%"
      height="100%"
      font-size=".95rem"
      border-radius="0"
      v-model="inputData"
    ></code-editor>
  </el-card>
</template>

<style scoped lang="scss">
@import "@/styles/components.scss";
</style>
