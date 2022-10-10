// https://v3.nuxtjs.org/api/configuration/nuxt.config
export default defineNuxtConfig({
    meta: {
        title: 'τ-rine',
        meta: [
            { charset: 'utf-8' },
            { name: 'viewport', content: 'width=device-width, initial-scale=1' },
            { hid: 'description', name: 'description', content: 'τ-rine est un groupe d\'enthousiaste en sécurité et d\'étudiants de l\'école d\'ingénieur ESIEA.' },
        ],
        link: [
            { rel: 'icon', type: 'image/x-icon', href: '/taurine_icon.png' }
        ],
    },
    vite: {
        css: {
            preprocessorOptions: {
                scss: {
                    additionalData: ['@use "@/assets/style/_variables.scss" as *;']
                }
            }
        }
    },
    css: [
        '@/assets/style/main.scss',
    ],
    modules: [
        '@nuxt/content'
    ],
    content: {
        highlight: {
            // Theme used in all color schemes.
            theme: 'dracula',
            preload: [
                'c',
                'cpp',
                'java',
                'python',
                'javascript',
                'json',
                'typescript',
                'js',
                'ts',
                'py',
                'bash',
                'rust',
            ]
        }
    },
})
