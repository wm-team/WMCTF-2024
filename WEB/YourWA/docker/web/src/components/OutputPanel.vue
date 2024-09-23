<script setup lang="ts">
import CodeEditor from "./CodeEditor.vue";

defineProps<{ gridClass: string }>();

const outputData = defineModel<string>({ default: "" });
</script>

<template>
  <el-card :class="gridClass">
    <code-editor
      :line-nums="true"
      :read-only="true"
      :ansi-mode="true"
      :languages="[['plaintext', 'PlainText', 'output.txt']]"
      :display-language="false"
      :display-header-text="true"
      header-text="OUTPUT"
      :header="true"
      :tab-space="4"
      :wrap="false"
      placeholder="Output"
      theme="vs2015"
      width="100%"
      height="100%"
      font-size=".95rem"
      border-radius="0"
      v-model="outputData"
    ></code-editor>
  </el-card>
</template>

<style scoped lang="scss">
@import "@/styles/components.scss";
</style>
