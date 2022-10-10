<script setup lang="ts">
const { tag } = defineProps<{ tag: string }>()
const router = useRouter()

</script>

<template>
    <RouterLink :to="`/articles?tag=${tag}`" class="badge">
        {{ tag }}
    </RouterLink>
</template>

<style lang="scss" scoped>
.badge {
    display: inline-block;
    font-size: 85%;
    line-height: 1;
    white-space: nowrap;
    vertical-align: baseline;

    padding: 0.3rem 0.5rem;
    text-align: center;
    border: 1px solid $gray-color;
    color: $gray-color;
    border-radius: 0.358rem;
}
</style>
