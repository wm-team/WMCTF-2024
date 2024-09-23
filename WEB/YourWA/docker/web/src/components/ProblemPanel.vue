<script setup lang="ts">
import markdownit from "markdown-it";
import { ProblemResponse } from "@/scripts/api";
import sendXhr, { replaceParam } from "@/scripts/xhr";
import { ElMessage } from "element-plus";
import { ref } from "vue";

const md = markdownit();

const props = defineProps<{ gridClass: string; apiProblem: string }>();

const displayProblemText = ref<boolean>(false);
const problemTitle = ref<string>(render("Problem Title"));
const problemDescription = ref<string>(render("Problem Description"));

function render(text: string) {
  let html = md.render(text);
  // html = html.replace(/(^|<\/?[^>]+>)([^<]+)(<[^>\/]+>|$)/g, (match, p1, p2, p3) => {
  //   if (!p2.trim()) return match;
  //   return `${p1}<span>${p2}</span>${p3}`;
  // });
  return html;
}

sendXhr({
  method: "GET",
  url: replaceParam(props.apiProblem, { id: 0 }),
  callback(xhr) {
    if (xhr.status === 200) {
      try {
        const resp: ProblemResponse = JSON.parse(xhr.responseText);
        problemTitle.value = render(resp.data.title);
        problemDescription.value = render(resp.data.description);
        displayProblemText.value = true;
      } catch (e) {
        ElMessage.error("Error loading problem");
      }
    } else if (xhr.status === 404) {
      ElMessage.error("Problem not found");
      try {
        const resp: ProblemResponse = JSON.parse(xhr.responseText);
        problemTitle.value = render(resp.data.title);
        problemDescription.value = render(resp.data.description);
        displayProblemText.value = true;
      } catch (e) {}
    } else {
      ElMessage.error("Error loading problem");
    }
  },
  onerror(err) {
    console.error(err);
    ElMessage.error("Error loading problem");
  },
});
</script>

<template>
  <el-card :class="gridClass">
    <template #header>
      <div
        class="card-header text-bold text-xl content-markdown"
        :class="{ 'opacity-0': !displayProblemText }"
        v-html="problemTitle"
      ></div>
    </template>
    <div
      class="margin-vertical-none content-markdown"
      :class="{ 'opacity-0': !displayProblemText }"
      v-html="problemDescription"
    ></div>
  </el-card>
</template>

<style lang="scss">
@import "@/styles/components.scss";

$p-margin-top: 0.5rem;

.el-card__header:has(.content-markdown) {
  $adjust: 0.5rem;
  padding-top: calc(var(--el-card-padding) - #{$adjust} - #{$p-margin-top});
  padding-bottom: calc(var(--el-card-padding) - #{$adjust});
}
.el-card__body:has(.content-markdown) {
  $adjust: 0.3rem;
  padding-top: calc(var(--el-card-padding) - #{$adjust} - #{$p-margin-top});
  padding-bottom: calc(var(--el-card-padding) - #{$adjust});
}

.content-markdown {
  line-height: 1.5;
  word-wrap: break-word;
  p {
    margin-top: $p-margin-top;
    margin-bottom: 0;
  }
  code {
    background: var(--el-color-primary-light-9);
    color: var(--el-color-primary);
    border-radius: 0.35rem;
    font-size: 0.9;
    line-height: 1.25;
    padding: 0.1rem 0.3rem;
    white-space: break-spaces;
  }
}
</style>
