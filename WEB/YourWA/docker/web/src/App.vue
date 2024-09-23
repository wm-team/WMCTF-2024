<script setup lang="ts">
import ProblemPanel from "@/components/ProblemPanel.vue";
import CodePanel, {
  PropUploadFunction,
  PropCancelFunction,
  PropRunCodeFunction,
  PropSubmitCodeFunction,
} from "@/components/CodePanel.vue";
import sendXhr, { replaceParam } from "@/scripts/xhr";
import {
  CancelResponse,
  RunCodeResponse,
  SubmitCodeResponse,
  UploadErrorResponse,
  UploadSuccessResponse,
} from "@/scripts/api";
import { ElMessage, ElNotification } from "element-plus";
import InputPanel from "@/components/InputPanel.vue";
import OutputPanel from "@/components/OutputPanel.vue";
import { ref } from "vue";

const codeValue = ref<string>("");
const inputValue = ref<string>("1\n2\n");
const outputValue = ref<string>("");
const uuid = ref<string>("");
const api = {
  problem: "/api/problem/:id",
  upload: "/api/upload",
  cancel: "/api/cancel/:uuid",
  run: "/api/run",
  runWithUUID: "/api/run/:uuid",
  submit: "/api/submit",
  submitWithUUID: "/api/submit/:uuid",
};

function parseJSON<T>(str: string): T | null {
  try {
    return <T>JSON.parse(str);
  } catch (e) {
    return null;
  }
}

const etypeMap = {
  RTE: "Runtime Error",
  TLE: "Time Limit Exceeded",
  SE: "System Error",
  CE: "Compile Error",
  UKE: "Unknown Error",
};

const upload: PropUploadFunction = (info, submit, done, close, changeStatus) => {
  changeStatus({
    // disableInput: true,
    disableUpload: true,
  });
  let did = submit({
    autofocus: true,
    onsuccess: (resp: UploadSuccessResponse) => {
      if (resp.code !== 200) {
        ElMessage.error(`Unexpected response code: ${resp.code}`);
        done();
        return;
      }
      let langId = {
        js: "javascript",
        ts: "typescript",
      }[info.entryFile.split(".").pop() || ""];
      changeStatus({ newLanguage: langId }); // langauge has to be changed before code
      changeStatus({ uploadMode: true, code: resp.data.content, uuid: resp.data.id });
      ElMessage.success("Upload success");
      if (resp.data.absent) {
        ElNotification({
          title: "Warning",
          message: "Entry file not exists, please complete it manually.",
          type: "warning",
          position: "bottom-right",
          duration: 5000,
        });
      }
      close();
      done();
    },
    onerror: (err) => {
      let json = parseJSON<UploadErrorResponse>(err.message);
      if (json !== null && typeof json.code === "number" && typeof json.message === "string") {
        ElMessage.error(`Error ${json.code}: ${json.message}`);
      } else ElMessage.error("Error when uploading");
      changeStatus({
        disableInput: false,
        disableUpload: false,
      });
      done();
    },
  });
  if (!did.sent) {
    ElMessage.warning(did.reason as string);
    changeStatus({
      disableInput: false,
      disableUpload: false,
    });
    done();
  }
};

const cancel: PropCancelFunction = (info, changeStatus) => {
  if (!info.uuid) {
    changeStatus({
      uploadMode: false,
      code: "",
      uuid: "",
    });
    return;
  }
  sendXhr({
    url: replaceParam(info.apiAddr, { uuid: info.uuid }),
    method: info.apiMethod,
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    callback: (xhr) => {
      if (xhr.status !== 200) {
        const data = parseJSON<CancelResponse>(xhr.responseText);
        if (data === null) ElMessage.error("Error when cancelling");
        else ElMessage.error(`Error ${data.code}: ${data.message}`);
      }
    },
    onerror: (err) => {
      console.error(err);
      ElMessage.error("Error when cancelling");
    },
  });
  changeStatus({
    uploadMode: false,
    code: info.langSettings[info.language].tmpl,
    uuid: "",
  });
};

const runCode: PropRunCodeFunction = (info, done) => {
  let apiAddr = api.run;
  let apiMethod = "POST";
  if (info.uploadMode && info.uuid) {
    apiAddr = replaceParam(api.runWithUUID, { uuid: info.uuid });
  } else if (info.uploadMode && !info.uuid) {
    ElNotification({
      title: "Error",
      message: "Uploaded files expired, please re-upload.",
      type: "error",
      position: "bottom-right",
      duration: 5000,
    });
    done();
  }
  sendXhr({
    url: apiAddr,
    method: apiMethod,
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    callback: (xhr) => {
      let data = parseJSON<RunCodeResponse>(xhr.responseText);
      if (data === null) ElMessage.error("Error when running code");
      else {
        if (data.result.error) {
          ElMessage.warning({
            message: "Run Code: " + etypeMap[data.result.etype || "UKE"],
            duration: 5000,
          });
          outputValue.value = data.result.stderr;
        } else {
          ElMessage.success("Run Code: Success");
          outputValue.value = data.result.stdout;
        }
      }
      done();
    },
    onerror: (err) => {
      console.error(err);
      ElMessage.error("Error when running code");
      done();
    },
    body: new URLSearchParams({
      code: info.code,
      input: inputValue.value,
      ...(info.uploadMode ? {} : { ext: info.langSettings[info.language].ext }),
    }),
  });
};

const submitCode: PropSubmitCodeFunction = (info, done) => {
  let apiAddr = api.submit;
  let apiMethod = "POST";
  if (info.uploadMode && info.uuid) {
    apiAddr = replaceParam(api.submitWithUUID, { uuid: info.uuid });
  } else if (info.uploadMode && !info.uuid) {
    ElNotification({
      title: "Error",
      message: "Uploaded files expired, please re-upload.",
      type: "error",
      position: "bottom-right",
      duration: 5000,
    });
    done();
  }
  sendXhr({
    url: apiAddr,
    method: apiMethod,
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    callback: (xhr) => {
      let data = parseJSON<SubmitCodeResponse>(xhr.responseText);
      if (data === null) {
        ElMessage.error("Error when submitting");
        done();
      } else if (data.result.error) {
        done("warning", etypeMap[data.result.etype || "UKE"]);
      } else if (data.result.check) {
        done("success", "Answer Correct");
      } else {
        done("error", "Wrong Answer");
      }
    },
    onerror: (err) => {
      console.error(err);
      ElMessage.error("Error when submitting");
      done();
    },
    body: new URLSearchParams({
      code: info.code,
      input: inputValue.value,
      ...(info.uploadMode ? {} : { ext: info.langSettings[info.language].ext }),
    }),
  });
};
</script>

<template>
  <div class="grid-main">
    <ProblemPanel grid-class="grid-area_title" :api-problem="api.problem" />
    <CodePanel
      grid-class="grid-area_code"
      v-model="codeValue"
      v-uuid="uuid"
      :prevent-close="false"
      method-upload="POST"
      :api-upload="api.upload"
      accept-upload=".zip"
      method-cancel="POST"
      :api-cancel="api.cancel"
      :upload="upload"
      :cancel="cancel"
      :run-code="runCode"
      :submit-code="submitCode"
    />
    <InputPanel grid-class="grid-area_input" v-model="inputValue" />
    <OutputPanel grid-class="grid-area_output" v-model="outputValue" />
  </div>
</template>

<style lang="scss">
@import "@/styles/layout.scss";

#app {
  height: 100%;
}

body {
  margin: 0;
  padding: 0;
  height: 100vh;
}
</style>
