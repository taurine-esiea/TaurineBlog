<script lang="ts" setup>
useHead({
    title: 'τ-rine - About us',
})

</script>

<template>
    <div>
        <h1>
            About <span>us</span>
        </h1>
        <p>
            We’re a bunch of security enthusiasts and students from the <a href="https://www.esiea.fr" target="_blank"
                rel="noopener noreferrer">ESIEA engineering school</a>. We aim to work on
            various security
            related subjects. On this website you will mainly find some write-ups about CTF challenges and also some
            articles.
        </p>

        <p>
            Lorem ipsum dolor sit amet consectetur adipisicing elit. Nesciunt molestias est voluptatibus, saepe quod
            fugit id quasi amet veritatis accusantium cum cupiditate nisi. Magnam possimus veniam labore voluptatem
            autem sequi.
        </p>

        <div class="img-container">
            <img src="@/assets/images/taurine_head_border.png" alt="Logo club sécu Esiea" />
        </div>
    </div>
</template>

<style lang="scss">
h1 {
    span {
        color: $primary-color;
    }
}

.img-container {
    display: flex;
    justify-content: center;
    margin-top: 3rem;

    img {
        max-width: 200px;
    }
}
</style>
