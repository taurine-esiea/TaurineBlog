

export function useLastestArticles() {
    const latestArticles = ref([])


    const query = queryContent('blog').sort(
        { createdAt: -1 }
    ).limit(6).find()

    query.then(articles => {
        latestArticles.value = articles
    })

    return {
        latestArticles
    }
}
