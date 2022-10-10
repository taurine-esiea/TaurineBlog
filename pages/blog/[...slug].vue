<script setup lang="ts">

const route = useRoute()
const article = await queryContent(route.path).findOne()
const { latestArticles } = useLastestArticles()

const [prevArticle, nextArticle] = await queryContent('blog')
    .sort({ createdAt: -1 })
    .findSurround(article._path)

</script>

<template>
    <div>
        <NuxtLink to="/articles" class="articles-list">
            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none"
                stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
                class="feather feather-arrow-left">
                <line x1="19" y1="12" x2="5" y2="12"></line>
                <polyline points="12 19 5 12 12 5"></polyline>
            </svg> Liste des articles
        </NuxtLink>
        <div class="tags">
            <BadgeTag :tag="tag" v-for="tag in article.tags" /> - {{ new Intl.DateTimeFormat('fr-FR').format(new
            Date(article.createdAt))}}
        </div>
        <div class="blog-content">
            <ContentDoc />
        </div>
        <div :class="`action-articles ${!prevArticle ? 'no-previous' : ''}`">
            <Button v-if="prevArticle" :to="prevArticle._path" variant="outline">
                <div style="display: flex; gap: .5rem; align-items: center;">
                    <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 22 22" fill="none"
                        stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
                        class="feather feather-arrow-left">
                        <line x1="19" y1="12" x2="5" y2="12"></line>
                        <polyline points="12 19 5 12 12 5"></polyline>
                    </svg>
                    Previous article
                </div>
            </Button>
            <Button v-if="nextArticle" :to="nextArticle._path" variant="outline">
                <div style="display: flex; gap: .5rem; align-items: center;">
                    Next article <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 22 22"
                        fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"
                        stroke-linejoin="round" class="feather feather-arrow-right">
                        <line x1="5" y1="12" x2="19" y2="12"></line>
                        <polyline points="12 5 19 12 12 19"></polyline>
                    </svg>
                </div>
            </Button>
        </div>
        <div class="latest-articles">
            <hr>
            <h2>
                Latest articles
            </h2>
            <div class="articles">
                <ArticleCard :article="article" v-for="article in latestArticles" />
            </div>
        </div>
    </div>
</template>

<style lang="scss">
.tags {
    margin-top: 1rem;
    display: flex;
    gap: .5rem;
    color: $gray-color;
}

.blog-content {
    h1 {
        margin-top: .5em;
        color: $primary-color;
        font-size: 32px;
    }
}

.articles-list {
    display: flex;
    gap: .2rem;
    font-size: 16px;
    color: inherit;
}

.action-articles {
    margin-top: 4rem;
    display: flex;
    justify-content: space-between;

    &.no-previous {
        justify-content: end;
    }
}

.latest-articles {

    hr {
        margin-top: 3rem;
        margin-bottom: 2.5rem;
    }

    h2 {
        // color: $primary-color;
        font-size: 28px;
    }

    .articles {
        display: grid;
        grid-template-columns: repeat(2, 1fr);
    }
}
</style>
