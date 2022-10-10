<script setup lang="ts">
import { ParsedContent } from '@nuxt/content/dist/runtime/types';

const { article } = defineProps<{ article: ParsedContent }>()

</script>

<template>
    <div class="article">
        <RouterLink :to="article._path">
            <h3>
                {{ article.title }}
            </h3>
            <p>
                {{ article.description}}
            </p>
        </RouterLink>
        <div class="tags">
            <BadgeTag v-for="tag in article.tags" :tag="tag" /> - {{ new Intl.DateTimeFormat('fr-FR').format(new
            Date(article.createdAt))}}
        </div>
        <hr>
    </div>
</template>

<style lang="scss" scoped>
.article {
    padding: 10px 0;
    height: fit-content;

    // h3 {
    //     color: $primary-color;
    // }

    hr {
        margin-top: 1.5rem;
        width: 30%;
    }

}

a {
    color: inherit;
}

.tags {
    display: flex;
    gap: .5rem;

    color: $gray-color;
}
</style>
