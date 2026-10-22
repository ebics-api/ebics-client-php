FROM php:8.5.12-cli

RUN apt-get update && apt-get install -y \
    libpq-dev \
    libxml2-dev \
    zlib1g-dev \
    git \
    zip \
    unzip \
    libssh-dev \
    libzip-dev \
    sudo \
    libwebp-dev \
    libjpeg62-turbo-dev \
    libpng-dev \
    libxpm-dev \
    libfreetype6-dev \
    && rm -rf /var/lib/apt/lists/*

RUN docker-php-ext-configure gd \
    --with-webp \
    --with-jpeg \
    --with-xpm \
    --with-freetype

RUN pecl install xdebug-3.5.1
RUN docker-php-ext-enable xdebug
RUN docker-php-ext-install bcmath
RUN docker-php-ext-install zip
RUN docker-php-ext-install gd

# Install composer
RUN ln -sf /usr/local/bin/php /usr/bin/php && \
    curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

WORKDIR /var/www/ebics-client-php
