<script setup lang="ts">
import { ref, h } from "vue";
import CodeEditor from "./CodeEditor.vue";
import UploadForm, { UploadFormData, UploadFunctionOptions } from "./UploadForm.vue";
import { Upload, CircleClose } from "@element-plus/icons-vue";
import { ElMessageBox, ElAlert } from "element-plus";

type SupportLanguage = "javascript" | "typescript";
interface ChangeStatusOptions {
  uploadMode: boolean;
  code: string;
  uuid: string;
  disableInput: boolean;
  disableUpload: boolean;
  preventOperateBtn: boolean;
  newLanguage: SupportLanguage | string;
}
type ChangeStatusFunction = (opts: Partial<ChangeStatusOptions>) => void;
type LanguageSetting = {
  tmpl: string;
  ext: string;
  displayName: string;
};
export type PropUploadFunction = (
  info: UploadFormData,
  submit: (options: UploadFunctionOptions) => { sent: boolean; reason?: string },
  done: () => void,
  close: (abort?: boolean) => void,
  changeStatus: ChangeStatusFunction
) => void;
export type PropCancelFunction = (
  info: {
    uuid: string;
    uploadMode: boolean;
    code: string;
    apiMethod: string;
    apiAddr: string;
    language: SupportLanguage;
    langSettings: Record<SupportLanguage, LanguageSetting>;
    [k: string]: any;
  },
  changeStatus: ChangeStatusFunction
) => void;
export type PropRunCodeFunction = (
  info: {
    uploadMode: boolean;
    code: string;
    uuid: string;
    language: SupportLanguage;
    langSettings: Record<SupportLanguage, LanguageSetting>;
    [k: string]: any;
  },
  done: () => void
) => void;
export type PropSubmitCodeFunction = (
  info: {
    uploadMode: boolean;
    code: string;
    uuid: string;
    language: SupportLanguage;
    langSettings: Record<SupportLanguage, LanguageSetting>;
    [k: string]: any;
  },
  done: (type?: "success" | "warning" | "error" | "info", msg?: string) => void
) => void;

const props = withDefaults(
  defineProps<{
    gridClass: string;
    upload?: PropUploadFunction;
    cancel?: PropCancelFunction;
    runCode?: PropRunCodeFunction;
    submitCode?: PropSubmitCodeFunction;
    uploadMode?: boolean;
    preventClose?: boolean; // prevent close event when uploading
    acceptUpload?: string;
    methodUpload?: string;
    methodCancel?: string;
    apiUpload: string;
    apiCancel: string;
  }>(),
  {
    gridClass: "",
    upload: <PropUploadFunction>((_, __, done) => {
      done();
    }),
    cancel: <PropCancelFunction>((info, changeStatus) => {
      changeStatus({
        uploadMode: false,
        code: info.langSettings[info.language].tmpl,
        uuid: "",
      });
    }),
    runCode: <PropRunCodeFunction>((_, done) => {
      done();
    }),
    submitCode: <PropSubmitCodeFunction>((_, done) => {
      done();
    }),
    uploadMode: false,
    preventClose: false,
    acceptUpload: "",
    methodUpload: "POST",
    methodCancel: "POST",
  }
);

let currentLanguage: SupportLanguage = "javascript";

const languageSettings: Record<SupportLanguage, LanguageSetting> = {
  javascript: {
    tmpl: `function solution(input, output) {
  let line1 = input()
  let line2 = input()
  output(line1, "->", line2)
}`,
    ext: "js",
    displayName: "JavaScript",
  },
  typescript: {
    tmpl: `function solution(input: () => string, output: (...s: any[]) => void) {
  let line1 = input()
  let line2 = input()
  output(line1, "->", line2)
}`,
    ext: "ts",
    displayName: "TypeScript",
  },
};

const codeModelValue = defineModel<string>({ default: "" });
const uuidModelValue = defineModel<string>("uuid", { default: "" });
const uploadMode = ref<boolean>(false);

const elemCodeEditor = ref();
const elemUploadForm = ref<InstanceType<typeof UploadForm>>();

const preventOperateBtn = ref<boolean>(false);
const displayUploadForm = ref<boolean>(false);
const disableInput = ref<boolean>(false);
const disableUpload = ref<boolean>(false);
const onUploading = ref<boolean>(false);
const onRunningCode = ref<boolean>(false);
const onSubmittingCode = ref<boolean>(false);

const preventify = (fn: Function, preventVal?: any) => {
  return ((...args: any[]) => {
    if (preventOperateBtn.value) return preventVal;
    return fn(...args);
  })();
};

if (!codeModelValue.value) {
  codeModelValue.value = languageSettings[currentLanguage].tmpl;
}

const onSwitchLanguage = (language: SupportLanguage) => {
  if (codeModelValue.value === languageSettings[currentLanguage].tmpl) {
    codeModelValue.value = languageSettings[language].tmpl;
  }
  currentLanguage = language;
};

const closeUploadDialog = () => {
  if (props.preventClose && onUploading.value) return;
  elemUploadForm.value?.abort();
  displayUploadForm.value = false;
  // restore status
  onUploading.value = false;
  preventOperateBtn.value = false;
  disableInput.value = false;
  disableUpload.value = false;
};

const openUploadDialog = () => {
  displayUploadForm.value = true;
  preventOperateBtn.value = true;
  // ? DO WE NEED TO RESTORE THESE
  disableInput.value = false;
  disableUpload.value = false;
};

function _changeStatus(opts: Partial<ChangeStatusOptions>) {
  if (typeof opts.uploadMode !== "undefined") {
    uploadMode.value = opts.uploadMode;
  }
  if (typeof opts.uuid !== "undefined") {
    uuidModelValue.value = opts.uuid;
  }
  if (typeof opts.disableInput !== "undefined") {
    disableInput.value = opts.disableInput;
  }
  if (typeof opts.disableUpload !== "undefined") {
    disableUpload.value = opts.disableUpload;
  }
  if (typeof opts.preventOperateBtn !== "undefined") {
    preventOperateBtn.value = opts.preventOperateBtn;
  }
  // langauge has to be changed before code
  if (typeof opts.newLanguage !== "undefined") {
    for (let lang in languageSettings) {
      if (lang === opts.newLanguage) {
        elemCodeEditor.value?.setLanguage(languageSettings[<SupportLanguage>lang].displayName);
        codeModelValue.value = codeModelValue.value;
        break;
      }
    }
  }
  if (typeof opts.code !== "undefined") {
    codeModelValue.value = opts.code;
  }
}

let __timeoutSubmitUpload: NodeJS.Timeout | null = null;
const doFormUpload = (prevent: boolean = false, interval?: number) => {
  if (prevent && onUploading.value) return;
  if (prevent && uploadMode.value) return;
  if (typeof interval === "number" && interval > 0) {
    if (__timeoutSubmitUpload !== null) return;
    __timeoutSubmitUpload = setTimeout(() => {
      clearTimeout(__timeoutSubmitUpload!);
      __timeoutSubmitUpload = null;
    }, interval);
  }

  onUploading.value = true;
  function done() {
    onUploading.value = false;
  }
  function close(abort: boolean = false) {
    if (abort) {
      elemUploadForm.value?.abort();
      displayUploadForm.value = false;
    } else {
      displayUploadForm.value = false;
    }
    // restore status
    preventOperateBtn.value = false;
    onUploading.value = false;
    disableInput.value = false;
    disableUpload.value = false;
  }
  const data: UploadFormData = elemUploadForm.value!.getFormData();
  props.upload(data, elemUploadForm.value!.upload, done, close, _changeStatus);
};

const doCancelUploadStatus = () => {
  // ElMessageBox.confirm("This will make your files removed. Continue?").then(() => {
  const info = {
    uuid: uuidModelValue.value!,
    uploadMode: uploadMode.value,
    code: codeModelValue.value,
    apiMethod: props.methodCancel,
    apiAddr: props.apiCancel,
    language: currentLanguage,
    langSettings: languageSettings,
  };
  props.cancel(info, _changeStatus);
  // });
};

function showSubmitResult(type: "success" | "warning" | "error" | "info", msg: string) {
  return ElMessageBox({
    // title: "",
    message: h(ElAlert, {
      showIcon: true,
      type: type,
      title: msg,
      closable: false,
      class: "__alert-result",
    }),
    showCancelButton: false,
    showConfirmButton: false,
    showClose: false,
    lockScroll: true,
    closeOnClickModal: true,
    closeOnPressEscape: true,
  });
}

function doRunCode() {
  const info = {
    uploadMode: uploadMode.value,
    code: codeModelValue.value,
    uuid: uuidModelValue.value,
    language: currentLanguage,
    langSettings: languageSettings,
  };
  preventOperateBtn.value = true;
  onRunningCode.value = true;
  function done() {
    onRunningCode.value = false;
    preventOperateBtn.value = false;
  }
  props.runCode(info, done);
}

function doSubmitCode() {
  const info = {
    uploadMode: uploadMode.value,
    code: codeModelValue.value,
    uuid: uuidModelValue.value,
    language: currentLanguage,
    langSettings: languageSettings,
  };
  preventOperateBtn.value = true;
  onSubmittingCode.value = true;
  function done(type?: "success" | "warning" | "error" | "info", msg?: string) {
    onSubmittingCode.value = false;
    if (typeof type !== "undefined" && typeof msg !== "undefined") {
      showSubmitResult(type!, msg!);
    }
    preventOperateBtn.value = false;
  }
  props.submitCode(info, done);
}
</script>

<template>
  <el-card :class="gridClass">
    <code-editor
      ref="elemCodeEditor"
      :line-nums="true"
      :read-only="false"
      :languages="[
        ['javascript', 'JavaScript', 'code.js'],
        ['typescript', 'TypeScript', 'code.ts'],
      ]"
      :display-language="true"
      :display-header-text="false"
      :header="true"
      :tab-space="4"
      :wrap="false"
      placeholder="// Type your code here..."
      theme="vs2015"
      width="100%"
      height="100%"
      font-size=".95rem"
      border-radius="0"
      v-model="codeModelValue"
      @lang="onSwitchLanguage"
    ></code-editor>
    <template #footer>
      <el-row>
        <el-col :span="8">
          <el-button type="primary" text v-if="!uploadMode" @click="preventify(openUploadDialog)">
            <el-icon class="el-icon--left">
              <Upload />
            </el-icon>
            Upload
          </el-button>
          <el-popconfirm
            popper-class="__popclose"
            placement="top-start"
            title="This will make your files removed. Continue?"
            :width="200"
            trigger="click"
            :disabled="preventify(() => false, true)"
            @confirm="preventify(doCancelUploadStatus)"
            confirm-button-text="Yes"
            cancel-button-text="No"
          >
            <template #reference>
              <el-button type="warning" text v-if="uploadMode">
                <el-icon class="el-icon--left"><CircleClose /></el-icon>
                Cancel
              </el-button>
            </template>
          </el-popconfirm>
        </el-col>
        <el-col :span="16" class="align-right">
          <el-button type="primary" :loading="onRunningCode" @click="preventify(doRunCode)">
            Run Code
          </el-button>
          <el-button type="primary" :loading="onSubmittingCode" @click="preventify(doSubmitCode)">
            Submit
          </el-button>
        </el-col>
      </el-row>
    </template>
  </el-card>
  <!-- upload form dialog -->
  <el-dialog
    v-model="displayUploadForm"
    destroy-on-close
    lock-scroll
    :close-on-press-escape="false"
    :close-on-click-modal="!onUploading"
    width="100%"
    :class="{
      '__dialog-upload': true,
      'on-uploading': onUploading,
    }"
    title="Upload"
    @close="closeUploadDialog"
    draggable
  >
    <UploadForm
      ref="elemUploadForm"
      :disable-input="disableInput"
      :disable-upload="disableUpload"
      :action="apiUpload"
      :method="methodUpload"
      :accept="acceptUpload"
      @entered="() => doFormUpload(true, 300)"
    />
    <el-col class="align-right margin-top-md">
      <el-button @click="closeUploadDialog">Cancel</el-button>
      <el-button type="primary" @click="doFormUpload" :loading="onUploading">Upload</el-button>
    </el-col>
  </el-dialog>
</template>

<style scoped lang="scss">
@import "@/styles/components.scss";
</style>

<style lang="scss">
.el-overlay > [role="dialog"] {
  padding: 16px;
}

.el-overlay > [role="dialog"]:has(.__dialog-upload) {
  .__dialog-upload {
    cursor: default;
    max-width: 650px !important;
  }
  &:has(.on-uploading) {
    cursor: not-allowed;
  }
}

.el-overlay > [role="dialog"]:has(.__alert-result) {
  cursor: pointer;

  .el-message-box {
    cursor: default;
    padding: 0;
    background-color: transparent;
    transform: scale(1.5);
    width: min-content;
    .el-message-box__btns {
      display: none;
    }
  }

  .__alert-result {
    width: max-content;
    padding: 12px 16px;
    cursor: cell;
    user-select: none;
    .el-alert__icon {
      font-size: var(--el-alert-icon-large-size);
      width: var(--el-alert-icon-large-size);
    }
    .el-alert__title {
      font-size: calc(var(--el-alert-icon-large-size) - 6px);
      font-weight: bold;
    }
  }
}

.__popclose {
  .el-popconfirm__main {
    align-items: flex-start;
  }
  .el-popconfirm__icon {
    margin-top: 5px;
    margin-right: 5px;
  }
}
</style>
