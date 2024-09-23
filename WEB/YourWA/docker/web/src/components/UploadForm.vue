<script setup lang="ts">
import { UploadFilled, Document } from "@element-plus/icons-vue";
import {
  InputInstance,
  UploadInstance,
  UploadFile,
  UploadRawFile,
  UploadUserFile,
} from "element-plus";
import { ref } from "vue";

withDefaults(
  defineProps<{
    action: string;
    method?: string;
    accept?: string;
    disableUpload?: boolean;
    disableInput?: boolean;
  }>(),
  {
    method: "POST",
    accept: "",
    disableUpload: false,
    disableInput: false,
  }
);

export type UploadFunctionOptions = {
  onsuccess: (response: any) => void;
  onerror: (err: Error) => void;
  autofocus?: boolean;
};
export type UploadFormData = ReturnType<typeof getFormData>;

const UploadFileList = ref<UploadUserFile[]>([]);
const uploadElem = ref<UploadInstance>();
const entryFileInputElem = ref<InputInstance>();
const entryFile = ref<string>("");
const disableUploadCallback = ref<boolean>(false);

const onExceed = (files: File[], uploadFiles: UploadUserFile[]) => {
  for (const file of files) {
    uploadFiles.shift();
    (file as UploadRawFile).uid = Date.now();
    let rawFile = file as UploadRawFile;
    uploadElem.value?.handleStart(rawFile);
  }
  console.log(files, uploadFiles);
};

const userOpts: UploadFunctionOptions = {
  onsuccess: () => {},
  onerror: () => {},
  autofocus: false,
};

let onUploadSuccss = (response: any /* , file: UploadRawFile, allUploadFiles: UploadFiles */) => {
  if (disableUploadCallback.value) return;
  userOpts.onsuccess(response);
  // console.log(response, file, allUploadFiles);
};

let onUploadError = (err: Error /* , file: UploadRawFile, allUploadFiles: UploadFiles */) => {
  if (disableUploadCallback.value) return;
  userOpts.onerror(err);
  // console.error(err, file, allUploadFiles);
};

const doUpload = (opts: UploadFunctionOptions) => {
  let files = UploadFileList.value;
  let needUploadCnt = 0;
  if (files) {
    for (const file of files) {
      if (file.status === "ready") needUploadCnt++;
    }
  }
  if (needUploadCnt === 0) return { sent: false, reason: "No file selected" };
  if (!entryFile.value) {
    if (Object.assign({ 0: userOpts.autofocus }, { 0: opts.autofocus })[0]) {
      entryFileInputElem.value?.focus();
    }
    return { sent: false, reason: "Entry file not set" };
  }
  Object.assign(userOpts, opts);
  uploadElem.value?.submit();
  return { sent: true };
};

const doAbort = () => {
  disableUploadCallback.value = true;
  for (const file of UploadFileList.value) {
    uploadElem.value?.abort(file as UploadFile);
  }
};

const getFormData = () => {
  return {
    entryFile: entryFile.value,
    files: UploadFileList.value,
  };
};

defineExpose({
  upload: doUpload,
  abort: doAbort,
  getFormData,
});
</script>

<template>
  <el-row class="margin-vertical-sm">
    <el-upload
      class="width-100"
      id="upload-elem"
      drag
      ref="uploadElem"
      name="file"
      :method="method"
      v-model:file-list="UploadFileList"
      :disabled="disableUpload"
      :data="{ entry: entryFile }"
      :show-file-list="true"
      :auto-upload="false"
      :on-exceed="onExceed"
      :on-success="onUploadSuccss"
      :on-error="onUploadError"
      :limit="1"
      :action="action"
      :accept="accept"
    >
      <el-icon class="el-icon--upload"><upload-filled /></el-icon>
      <div class="el-upload__text">Drop file here or <em>click to upload</em></div>
      <template #tip>
        <div class="el-upload__tip">
          JavasSript or TypeScript project:
          {{
            accept
              .split(",")
              .map((s) => "*" + s.trim())
              .join(", ")
          }}
        </div>
      </template>
    </el-upload>
  </el-row>

  <el-row class="margin-vertical-sm">
    <label for="input-entry-file">
      <span class="text-bold required-end">Entry file</span>
    </label>
  </el-row>
  <el-row class="margin-vertical-sm">
    <el-input
      id="input-entry-file"
      ref="entryFileInputElem"
      placeholder="index.js"
      v-model="entryFile"
      :disabled="disableInput"
      :maxlength="255"
      :show-word-limit="false"
      type="text"
      @keydown.enter="$emit('entered')"
    >
      <template #prefix>
        <el-icon><Document /></el-icon>
      </template>
    </el-input>
  </el-row>
</template>

<style scoped lang="scss">
@import "@/styles/components.scss";
</style>

<style lang="scss">
.el-message-box__message:has(#upload-elem) {
  width: 100%;
}
</style>
