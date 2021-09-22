<script lang="ts">
  import Nav from "./Nav.svelte";
  import { tab } from "../store";
  import Upload from "./Upload.svelte";

  let open: string;
  tab.subscribe((value) => (open = value));
</script>

<div>
  <Nav />
  <Upload />
</div>
