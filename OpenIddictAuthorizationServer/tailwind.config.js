module.exports = {
    content: [
        './Views/**/*.cshtml',
        './Pages/**/*.cshtml',
        './Pages/*.cshtml'
    ],
    theme: {
        extend: {
            fontFamily: {
                sans: ['Inter', 'ui-sans-serif', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'Helvetica Neue', 'Arial', 'Noto Sans', 'sans-serif'],
            },
            borderRadius: {
                'xl': '1rem',
                'lg': '0.5rem',
            },
            boxShadow: {
                'lg': '0 4px 6px -1px rgba(0, 0, 0, 0.2), 0 2px 4px -2px rgba(0, 0, 0, 0.1)',
                'md': '0 2px 4px -1px rgba(0, 0, 0, 0.15)',
            },
            transitionProperty: {
                'colors': 'background-color, border-color, color, fill, stroke',
                'shadow': 'box-shadow',
            },
            transitionDuration: {
                '200': '200ms',
            }
        },
    },
    plugins: [

    ],
}


