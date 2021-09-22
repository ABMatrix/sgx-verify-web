<script lang="ts">
  import Tailwind from "./components/Tailwinds.svelte";
  import { SvelteToast } from "@zerodevx/svelte-toast";
  import Home from "./page/Home.svelte";
  import { loginState } from "./store";
  let login: boolean = false;
  loginState.subscribe((value) => (login = value));
  const options = {
    duration: 5000,
    dismissable: true,
    initial: 1,
    progress: 0,
    reversed: true,
    intro: { x: 256 },
  };
</script>

<Tailwind />
<SvelteToast {options} />
<div>
  <Home />
</div>
