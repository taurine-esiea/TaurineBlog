<script lang="ts" setup>


const { label, checked, id } = defineProps<{
    label: string
    checked: boolean
    id?: string
}>()
const emit = defineEmits(['update:checked', 'change'])
</script>

<template>
    <div class="form-control">
        <input :id="id ? id : label" type="checkbox" :checked="checked"
            @input="emit('update:checked', $event.target.checked)" @change="$emit('change', $event.target.checked)" />
        <label :for="id ? id : label">
            <span>
                {{ label }}
            </span>
        </label>
    </div>
</template>

<style lang="scss" scoped>
.form-control {
    display: grid;
    grid-template-columns: 1rem auto;
    gap: 0.5rem;
    font-weight: 500;
    font-size: 1.1rem;
    // line-height: 1.1;
}

label {
    margin-left: .5rem;

    span {
        cursor: pointer;
    }
}

input {
    appearance: none;
    margin: 0;

    font: inherit;
    color: $primary-color;
    width: 1.25rem;
    height: 1.25rem;
    border: 1px solid $primary-color;
    border-radius: 0.15rem;
    transform: translateY(.1rem);

    display: grid;
    place-content: center;

    cursor: pointer;
}

input::before {
    content: "";
    width: 0.65rem;
    height: 0.65rem;
    transform: scale(0) translateY(-1rem);
    transition: 120ms transfrom ease-in-out;

    transform-origin: bottom left;
    clip-path: polygon(14% 44%, 0 58%, 50% 100%, 100% 16%, 90% 0%, 50% 62%);
    // origin :
    // clip-path: polygon(14% 44%, 0 65%, 50% 100%, 100% 16%, 80% 0%, 43% 62%);

    // transform-origin: bottom left;
    box-shadow: inset 1rem 1rem $primary-color;
}

input:checked::before {
    transform: scale(1) translateY(-.01rem);
}
</style>
