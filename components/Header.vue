<script setup lang="ts">

const isMobileNavBarOpen = ref(false)
const route = useRoute()

const isReadingArticle = computed(() => {
    return route.path.includes('/blog/')
})

</script>

<template>
    <div class="header-desktop">
        <NuxtLink to="/">
            <img src="@/assets/images/taurine_white_center.png" alt="Logo club sécu taurine esiea">
        </NuxtLink>
        <ul>
            <li>
                <NuxtLink to="/">
                    Home
                </NuxtLink>
            </li>
            <li>
                <NuxtLink to="/articles" :class="isReadingArticle ? 'router-link-active' : ''">
                    Articles
                </NuxtLink>
            </li>
            <li>
                <NuxtLink to="/about">
                    About
                </NuxtLink>
            </li>
        </ul>
    </div>
    <div class="header-mobile">
        <div class="navbar-open-btn" @click="isMobileNavBarOpen = true">
            <svg fill="#fff" viewBox="0 0 100 80" width="40" height="40">
                <rect width="100" height="10"></rect>
                <rect y="30" width="100" height="10"></rect>
                <rect y="60" width="100" height="10"></rect>
            </svg>
        </div>
        <div :class="`navbar ${isMobileNavBarOpen ? 'show' :'hide'}`">
            <NuxtLink to="/" class="img" @click="isMobileNavBarOpen = false">
                <img src="@/assets/images/taurine_white_center.png" alt="Logo club sécu taurine esiea">
            </NuxtLink>
            <ul @click="isMobileNavBarOpen = false">
                <li>
                    <NuxtLink to="/">
                        Home
                    </NuxtLink>
                </li>
                <li>
                    <NuxtLink to="/articles">
                        Articles
                    </NuxtLink>
                </li>
                <li>
                    <NuxtLink to="/about">
                        About
                    </NuxtLink>
                </li>
            </ul>
        </div>
        <div :class="`navbar-overlay ${isMobileNavBarOpen ? 'show' :'hide'}`" @click="isMobileNavBarOpen = false" />
    </div>
</template>

<style lang="scss" scoped>
.header-desktop {
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: $font-title;
    padding: .8rem 0;

    img {
        width: 150px;
        margin-right: 3.5rem;
    }

    ul {
        display: flex;
        gap: 3rem;
        list-style: none;
        margin-top: .15rem;

        li {
            a {
                color: $text-color;
                transition: color .3s;

                &:hover {
                    color: $primary-color;
                }

                &.router-link-active {
                    color: $primary-color;
                }
            }

        }
    }
}

.header-mobile {
    display: none;

    .navbar-open-btn {
        margin: 20px 0 0 20px;
    }

    .navbar-overlay {
        position: absolute;
        top: 0;
        width: 100%;
        height: 100%;
        background-color: rgba(34, 41, 47, .5);
        transition: opacity .3s;

        &.show {
            opacity: 1;
        }

        &.hide {
            opacity: 0;
            visibility: hidden;
        }
    }

    .navbar {
        z-index: 3;
        position: absolute;
        width: 250px;
        top: 0;
        height: 100%;
        background-color: #000;
        padding-top: 1rem;
        transition: transform .3s;

        .img {
            display: flex;
            justify-content: center;

            img {
                max-width: 180px;
            }
        }

        &.hide {
            transform: translateX(-250px);
        }

        ul {
            display: flex;
            flex-direction: column;
            gap: 1rem;
            list-style: none;
            margin-top: 2rem;
            font-family: $font-title;
            font-size: 18px;
            padding-left: 1.5rem;

            li {
                a {
                    color: $text-color;
                    transition: color .3s;

                    &:hover {
                        color: $primary-color;
                    }

                    &.router-link-active {
                        color: $primary-color;
                    }
                }

            }
        }
    }
}

@media (max-width: 750px) {
    .header-desktop {
        display: none;
    }

    .header-mobile {
        display: block;
    }
}
</style>
