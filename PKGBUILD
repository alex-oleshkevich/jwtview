pkgname=jwtview
pkgver=0.1.0
pkgrel=1
pkgdesc="Colorful CLI to inspect JWTs and verify JWT signatures"
arch=('x86_64')
url="https://github.com/alex-oleshkevich/jwtview"
license=('MIT')
depends=()
source=("jwtview-linux-x86_64.tar.gz::${url}/releases/download/v${pkgver}/jwtview-linux-x86_64.tar.gz")
sha256sums=('SKIP')

package() {
  cd "${srcdir}"
  tar -xzf jwtview-linux-x86_64.tar.gz
  install -Dm755 jwtview-linux-x86_64/jwtview "${pkgdir}/usr/bin/jwtview"
}
