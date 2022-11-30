#include <string.h>

#include <openssl/engine.h>

#include "e_lkcf_err.h"
#include "lkcf.h"
#include "lkcf_rsa.h"
//#include "lkcf_dh.h"
#include "log.h"

static const char *engine_id = "lkcf-engine";
static const char *engine_name = "A asymmetric engine based on Linux Kernel Crypto Framework.";

static int lkcf_engine_destroy(ENGINE *e);
static int lkcf_engine_init(ENGINE *e);

static int bind_lkcf_engine(ENGINE *e, const char *id)
{
	int ret = 0;
	const char* _id = strrchr(id, '/');
	if (!_id) {
		_id = id;
	} else {
		_id++;
	}
	if (_id && strncmp(engine_id, _id, strlen(engine_id))) {
		log_warn("ENGINE_id defined already! %s - %s", _id, engine_id);
		goto out;
	}

	if (!ENGINE_set_id(e, engine_id)) {
		log_error("Failed to set engine id");
		goto out;
	} 

	if (!ENGINE_set_name(e, engine_name)) {
		log_error("Failed to set engine name");
		goto out;
	}

	ERR_load_LKCF_strings();

	if (!ENGINE_set_RSA(e, lkcf_get_RSA_methods())) {
		log_error("Failed to set rsa methods");
		goto out;
	}

	ret = 1;
	ret &= ENGINE_set_init_function(e, lkcf_engine_init);
	ret &= ENGINE_set_destroy_function(e, lkcf_engine_destroy);
	if (ret == 0) {
		log_error("Failed to set engine destroy function");
	}

out:
	return ret;
}

static int lkcf_engine_init(ENGINE *e)
{
	int ret = 1;
	ret &= lkcf_init();	
	return ret;
}

static int lkcf_engine_destroy(ENGINE *e)
{
	lkcf_free_RSA_methods();	
	lkcf_destroy();
	ERR_unload_LKCF_strings();
	return 1;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind_lkcf_engine)
IMPLEMENT_DYNAMIC_CHECK_FN()
