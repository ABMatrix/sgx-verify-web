<script>
  import { shortPem, verify, valid } from "../api";
  import { toast } from "@zerodevx/svelte-toast";
  let file;
  let upload;
  let verified = false;
  let pem;
  let resultData;
  let isSgxCert;

  function onChange(e) {
    file = e.target.files[0];
    uploadFiles(file);
  }

  function uploadFiles() {
    if (file) {
      const reader = new FileReader();
      reader.addEventListener("load", (event) => {
        const isValid = valid(event.target.result);
        if (isValid) {
          pem = event.target.result;
        } else {
          toast.push("证书文件不正确")
          file = undefined;
        }
      });
      reader.readAsText(file);
    }
  }

  async function verifyCert() {
    let res = verify(pem);
    console.log(res);
    const result = JSON.parse(res);
    isSgxCert = result.result === "success";
    if (isSgxCert) {
      resultData = JSON.parse(result.data);
    } else {
      resultData = result.data;
    }
    verified = true;
  }

  function clearPem() {
    verified = false;
    resultData = undefined;
    pem = undefined;
    file = undefined;
  }
</script>

<section class="max-w-4xl mx-auto px-4 pt-24">
  <div class="flex flex-col space-y-4">
    <div class="w-full shadow-inner rounded-md bg-blue-100 p-4">
      <article
        aria-label="File Upload Modal"
        class="relative h-full flex flex-col "
        ondrop="dropHandler(event);"
        ondragover="dragOverHandler(event);"
        ondragleave="dragLeaveHandler(event);"
        ondragenter="dragEnterHandler(event);"
      >
        <!-- scroll area -->
        <section class="h-full overflow-auto p-8 w-full flex flex-col">
          {#if pem == null}
            <header
              class="border-dashed border-2 border-gray-400 py-12 flex flex-col justify-center items-center"
            >
              <p
                class="mb-3 font-semibold text-gray-900 flex flex-wrap justify-center"
              >
                <span>上传证书文件</span>
              </p>
              <input
                id="hidden-input"
                bind:this={upload}
                type="file"
                on:change={onChange}
                class="hidden"
              />
              <button
                id="button"
                on:click={upload.click()}
                class="mt-2 rounded-md px-3 py-1 bg-gray-200 hover:bg-gray-300 focus:shadow-outline focus:outline-none"
              >
                Upload a file
              </button>
            </header>
          {:else}
            <div
              class="text-yellow-600 break-words border-dashed border-2 border-gray-400 py-4 p-8"
            >
              <div>-----BEGIN CERTIFICATE-----</div>
              <div>{shortPem(pem)[0]}</div>
              <div>------</div>
              <div>{shortPem(pem)[1]}</div>
              <div>-----END CERTIFICATE-----</div>
            </div>
          {/if}
          {#if verified === true}
            <div>
              {#if isSgxCert}
                <div class="py-4 text-green-600">
                  <span />
                  <span class="text-xl"> 该证书为 SGX 证书 </span>
                </div>
                <ul class="list-disc list-inside break-words text-blue-600">
                  <li>
                    <span class="font-medium">Version:</span>
                    <span class="font-mono">{resultData.version}</span>
                  </li>
                  <li>
                    <span class="font-medium">Sign type:</span>
                    {resultData.signType}
                  </li>
                  <li>
                    <span class="font-medium">Mr Enclae:</span>
                    <span class="font-mono"
                      >{resultData.quoteReportBody.mrEnclave}</span
                    >
                  </li>
                  <li>
                    <span class="font-medium">Mr Signer:</span>
                    <span class="font-mono"
                      >{resultData.quoteReportBody.mrsigner}</span
                    >
                  </li>
                  <li>
                    <span class="font-medium">Report data:</span>
                    <span class="font-mono"
                      >{resultData.quoteReportBody.reportData}</span
                    >
                  </li>
                </ul>
              {:else}
                <div class="py-4 text-red-600">
                  <span />
                  <span class="text-xl"> 该证书非 SGX 证书</span>
                </div>
                <div>{resultData}</div>
              {/if}
              <div />
            </div>
          {/if}
          <!-- sticky footer -->
          <footer class="flex justify-center px-8 pb-8 pt-8">
            {#if !verified}
              <button
                type="button"
                on:click={verifyCert}
                disabled={pem == null}
                class="rounded-md px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white w-40 h-10 ring-4 ring-opacity-50 ring-blue-300 focus:shadow-outline focus:outline-none"
              >
                点击验证
              </button>
            {:else}
              <button
                type="button"
                on:click={clearPem}
                disabled={pem == null}
                class="rounded-md px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white w-40 h-10 ring-4 ring-opacity-50 ring-blue-300 focus:shadow-outline focus:outline-none"
                >重新上传
              </button>
            {/if}
          </footer>
        </section>
      </article>
    </div>
  </div>
  <section class="py-8 ">
    <!-- <div>常见问题</div>
    <ul>
      <li>
        <div>Sgx 服务器安全在哪里？</div>
        <div />
      </li>
      <li>
        <div>Sgx 证书验证过程？</div>
      </li>
    </ul> -->
    <div class="text-blue-600 py-4">Made by ❤️ @safematrix</div>
  </section>
</section>
