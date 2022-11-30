<script lang="ts" setup>

useHead({
    title: 'τ-rine - Home',
})

const { latestArticles } = useLastestArticles()

</script>

<template>
    <div>
        <div class="hero">
            <h1>
                τ<span class="dash">-</span>rine
            </h1>
            <p>
                ( Pronounced tau-rin, not t-rin )
            </p>
        </div>

        <main>
            <p>
                
                <center>
                    Technical blog of the
                    <a href="https://www.esiea.fr" target="_blank" rel="noopener noreferrer">
                        ESIEA
                    </a> cybersecurity club.
                </center>
            </p>
            <div class="last-content-wrapper">
                <h2>
                    <span>Latest</span> articles
                </h2>
                <ArticleCard :article="article" v-for="article in latestArticles" />
                <div class="see-more-section">
                    <Button variant="outline" to="/articles">
                        See more...
                    </Button>
                </div>
            </div>
        </main>
    </div>
</template>

<style lang="scss" scoped>
.hero {
    h1 {
        margin-top: 3rem;
        font-size: 4rem;
        text-align: center;
        font-family: $font-title;

        .dash {
            color: $primary-color;
        }
    }

    p {
        text-align: center;
        font-family: $font-code;
    }
}

main {
    margin-top: 3rem;
}

.last-content-wrapper {
    margin-top: 3rem;


    h2 {

        // mt
        span {
            color: $primary-color;
        }
    }

    .see-more-section {
        margin-top: 1rem;
        display: flex;
        justify-content: center;
    }
}
</style>
