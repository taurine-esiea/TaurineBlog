<script lang="ts" setup>
const { to, variant } = defineProps<{
    to: string
    variant: 'primary' | 'outline' | 'flat'
}>()
</script>


<template>
    <RouterLink :to="to" :class="`${variant}`">
        <slot />
    </RouterLink>
</template>

<style lang="scss" scoped>
a {
    border-radius: 25px;
    padding: 8px 20px 10px;
    font-size: 16px;
    transition: all .3s;


    &:focus {
        transform: scale(.95);
    }

    &.primary {
        background-color: $primary-color;
        color: $text-color;

    }

    &.outline {
        border: $text-color 1px solid;
        color: $text-color;

        &:hover {
            color: $primary-color;
            border-color: $primary-color;
        }
    }
}
</style>
