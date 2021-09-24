<script lang="ts">
  import { tab } from "../store";
  let open: string;
  tab.subscribe((value) => (open = value));
  function changeTab(name: string): void {
    tab.set(name);
  }

  let logo = "https://www.safematrix.io/_nuxt/img/logo.7234db3.png";
</script>

<div class="shadow w-full fixed z-10">
  <nav class="h-full bg-white z-1000 backdrop-filter backdrop-blur-lg bg-opacity-40">
    <div class="max-w-4xl mx-auto px-4 flex flex-row justify-between">
      <div class="text-xl my-auto text-blue-600 font-medium">SGX 证书验证</div>
      <div class="flex flex-row justify-items-center space-x-4 my-4">
        <div
          class="my-auto cursor-pointer hover:text-blue-400 font-mono active:underline text-blue-600"
          on:click={() => window.open("https://github.com/ABMatrix/sgx-verify-web")}
        >
          GitHub
        </div>
      </div>
    </div>
  </nav>
</div>
