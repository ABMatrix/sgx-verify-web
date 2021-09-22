import { writable } from 'svelte/store';

export const tab = writable('manage');
export const loginState = writable(false);