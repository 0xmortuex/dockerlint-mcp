FROM ruby:3.3-slim

ENV RAILS_ENV=production BUNDLE_WITHOUT="development:test"
WORKDIR /rails

RUN apt-get update -qq \
    && apt-get install -y --no-install-recommends build-essential libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY Gemfile Gemfile.lock ./
RUN bundle install && rm -rf ~/.bundle/ /usr/local/bundle/cache

COPY . .

RUN useradd rails --create-home --shell /bin/bash \
    && chown -R rails:rails log tmp
USER rails

EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost:3000/up || exit 1
CMD ["./bin/rails", "server", "-b", "0.0.0.0"]
