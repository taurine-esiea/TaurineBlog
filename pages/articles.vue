<script lang="ts" setup>

const route = useRoute()

useHead({
    title: 'τ-rine - Articles',
})


const types = [
    'Writeups',
    'Articles',
    'Projects',
]
const allTypesSelected = ref(true)
const selectedTypes = ref({
})

/**
 * 
 */
watch(selectedTypes, newSelectedTypes => {
    allTypesSelected.value = Object.values(
        newSelectedTypes
    ).reduce(
        (previous, current) => (!previous ? false : current)
    ) as boolean

    getArticles()
}, { deep: true })

types.forEach(type => {
    selectedTypes.value[type] = true
})

const allTypeSelectedChange = (checked: boolean) => {
    types.forEach(type => {
        selectedTypes.value[type] = checked
    })
}



const allTagsSelected = ref(true)
const tags = [
    'Crypto',
    'Forensic',
    'Hardware',
    'Misc',
    'Network',
    'pwn', // putain Pierre comment ça un P majuscule ?? ça a baisé tous mes tags si vous lisez ceci: PWN c'est en minuscule
    'Reverse',
    'Osint',
    'System',
    'Web',
    'Others',
]
const selectedTags = ref({})
tags.forEach(tag => {
    selectedTags.value[tag] = true
})

watch(selectedTags, newSelectedTags => {
    allTagsSelected.value = Object.values(
        newSelectedTags
    ).reduce(
        (previous, current) => (!previous ? false : current)
    ) as boolean

    getArticles()
}, { deep: true })

const allTagsSelectedChange = (checked: boolean) => {
    tags.forEach(type => {
        selectedTags.value[type] = checked
    })
}


const articles = ref([])

const getArticles = async () => {

    /**
     * Converti l'objet des type d'article sélectionnés en liste des types sélectionnés
     * {Writeups: true, Projects: false} -> ['Writeups']
     */
    const selectedTypesList = []
    Object.entries(selectedTypes.value).forEach(([type, selected]) => {
        if (selected) {
            selectedTypesList.push(type)
        }
    })

    const selectedTagsList = []
    Object.entries(selectedTags.value).forEach(([tag, selected]) => {
        if (selected) {
            selectedTagsList.push(tag)
        }
    })

    const data = await queryContent('blog')
        .where(
            {
                type: { $in: selectedTypesList },
                tags: { $in: selectedTagsList },
            }
        )
        .sort(
            { createdAt: -1 }
        ).find()

    articles.value = data
}



const selectOneTag = () => {
    tags.forEach(tag => {
        selectedTags.value[tag] = false
    })
    selectedTags.value[route.query.tag as string] = true
}

watch(() => route.query.tag, () => {
    selectOneTag()
})

if (route.query.tag) {
    selectOneTag()
}

</script>

<template>
    <div class="container">
        <div class="wrapper">
            <div class="sidebar">
                <h1>
                    Articles
                </h1>
                <hr>
                <div class="filters">
                    <div class="types">
                        <h4>
                            Types
                        </h4>
                        <FormCheckBox v-model:checked="allTypesSelected" id="tous-types" label="Tous"
                            @change="allTypeSelectedChange" />
                        <FormCheckBox v-for="typ in types" :label="typ" v-model:checked="selectedTypes[typ]" />
                    </div>
                    <div class="categories">
                        <h4>
                            Catégories
                        </h4>
                        <FormCheckBox v-model:checked="allTagsSelected" id="tous-tags" label="Tous"
                            @change="allTagsSelectedChange" />
                        <FormCheckBox v-for="tag in tags" :label="tag" v-model:checked="selectedTags[tag]" />
                    </div>
                </div>
            </div>
            <div v-if="articles.length === 0" class="articles-empty">
                <h2>
                    No article found :(
                </h2>
            </div>
            <div v-else class="articles">
                <ArticleCard :article="article" v-for="article in articles" />
            </div>
        </div>
    </div>
</template>


<style>
/* override */
/* .default-container {
    max-width: 1200px;
} */
</style>

<style lang="scss" scoped>
.wrapper {
    display: flex;
    gap: 1.5rem;
}

.articles {
    display: flex;
    flex-direction: column;
    width: 100%;

}

.articles-empty {
    width: 100%;
    margin-top: 3rem;
    display: flex;
    justify-content: center;
}

.sidebar {
    min-width: 230px;

    .types {
        margin-top: 1rem;
    }

    .categories {
        margin-top: 1rem;
    }
}

@media (max-width: 750px) {
    .wrapper {
        flex-direction: column;
    }

    .filters {
        display: flex;
        gap: 3rem;
    }
}
</style>
