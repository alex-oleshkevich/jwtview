pkgname=jwtview
pkgver=0.1.0
pkgrel=1
pkgdesc="Colorful CLI to inspect JWTs and optionally verify RS256 signatures"
arch=('x86_64')
url="https://github.com/alex-oleshkevich/jwtview"
license=('MIT')
depends=()
makedepends=('cargo')
source=("${pkgname}-${pkgver}.tar.gz::${url}/archive/refs/tags/v${pkgver}.tar.gz")
sha256sums=('SKIP')

build() {
  cd "${srcdir}/${pkgname}-${pkgver}"
  cargo build --release --locked
}

package() {
  cd "${srcdir}/${pkgname}-${pkgver}"
  install -Dm755 target/release/jwtview "${pkgdir}/usr/bin/jwtview"
  install -Dm644 LICENSE "${pkgdir}/usr/share/licenses/${pkgname}/LICENSE"
}
