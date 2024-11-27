PORTNAME=	hydra
DISTVERSIONPREFIX=	v
DISTVERSION=	2.2.0
CATEGORIES=	net
DIST_SUBDIR=	${PKGNAMEPREFIX}${PORTNAME}
PKGNAMEPREFIX=	ory-

MAINTAINER=	doceng@FreeBSD.org
COMMENT=	Fast and Flexible Static Site Generator built with love in GoLang
WWW=		https://www.ory.sh/hydra

LICENSE=	APACHE20
LICENSE_FILE=	${WRKSRC}/LICENSE

USES=		go:1.23,modules
USE_GITHUB= 	yes
USE_RC_SUBR=	hydra

GH_ACCOUNT=	ory
GO_MODULE=	github.com/ory/hydra/v2
GO_BUILDFLAGS=	-ldflags="-X github.com/ory/hydra/v2/driver/config.Version=${PORTVERSION}"

post-fetch:
	@${ECHO_MSG} "Fetching ${GO_MODNAME}/internal/httpclient dependency";
	(cd ${DISTDIR}/${DIST_SUBDIR}; [ -e internal/httpclient/go.mod ] || (\
		${MKDIR} internal/httpclient/; \
		${TAR} -zxf ${DISTNAME}${EXTRACT_SUFX} ${PORTNAME}-${PORTVERSION}/internal/httpclient/go.mod; \
		${CP} ${PORTNAME}-${PORTVERSION}/internal/httpclient/go.mod internal/httpclient/go.mod))

post-extract:
	@${MKDIR} ${GO_WRKSRC}/internal/httpclient;
	@${CP} -r ${WRKDIR}/${PORTNAME}-${PORTVERSION}/internal/httpclient ${GO_WRKSRC}/internal;

post-install:
	@${MKDIR} ${STAGEDIR}${PREFIX}/etc/hydra
	${INSTALL_DATA} ${WRKSRC}/contrib/quickstart/5-min/hydra.yml ${STAGEDIR}${PREFIX}/etc/hydra/hydra.yml.sample

.include <bsd.port.mk>
