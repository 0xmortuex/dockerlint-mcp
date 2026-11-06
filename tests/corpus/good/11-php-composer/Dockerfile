FROM composer:2.8 AS vendor
WORKDIR /app
COPY composer.json composer.lock ./
RUN composer install --no-dev --no-scripts --prefer-dist

FROM php:8.3-fpm-alpine
WORKDIR /var/www/html
RUN apk add --no-cache libzip-dev \
    && docker-php-ext-install zip
COPY --from=vendor /app/vendor ./vendor
COPY --chown=www-data:www-data . .
USER www-data
EXPOSE 9000
HEALTHCHECK --interval=30s --timeout=3s CMD php-fpm-healthcheck || exit 1
CMD ["php-fpm"]
