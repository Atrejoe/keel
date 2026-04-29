<template>
  <div class="main">
    <a-form
      v-if="basicAuthEnabled"
      id="formLogin"
      class="user-layout-login"
      ref="formLogin"
      :form="form"
      @submit="handleSubmit"
    >
      <a-form-item>
        <a-input
          size="large"
          type="text"
          placeholder="Your username"
          v-decorator="[
            'username',
            {rules: [{ required: true, message: 'Username required' }, { validator: handleUsernameOrEmail }], validateTrigger: 'change'}
          ]"
        >
          <a-icon slot="prefix" type="user" :style="{ color: 'rgba(0,0,0,.25)' }"/>
        </a-input>
      </a-form-item>

      <a-form-item>
        <a-input
          size="large"
          type="password"
          autocomplete="false"
          placeholder="Your password"
          v-decorator="[
            'password',
            {rules: [{ required: true, message: 'Invalid password' }], validateTrigger: 'blur'}
          ]"
        >
          <a-icon slot="prefix" type="lock" :style="{ color: 'rgba(0,0,0,.25)' }"/>
        </a-input>
      </a-form-item>
      <a-form-item style="margin-top:24px">
        <a-button
          size="large"
          type="primary"
          htmlType="submit"
          class="login-button"
          :loading="state.loginBtn"
          :disabled="state.loginBtn"
        >Login</a-button>
      </a-form-item>
    </a-form>

    <div v-if="oauthEnabled" :class="{ 'user-layout-login': true, 'oauth-section': basicAuthEnabled }">
      <a-button
        size="large"
        type="default"
        class="login-button"
        @click="handleOAuthLogin"
      >Login with OAuth</a-button>
    </div>

    <two-step-captcha
      v-if="requiredTwoStepCaptcha"
      :visible="stepCaptchaVisible"
      @success="stepCaptchaSuccess"
      @cancel="stepCaptchaCancel"
    ></two-step-captcha>
  </div>
</template>

<script>

export default {
  data () {
    return {
      customActiveKey: 'tab1',
      loginBtn: false,
      // login type: 0 email, 1 username, 2 telephone
      loginType: 0,
      requiredTwoStepCaptcha: false,
      stepCaptchaVisible: false,
      form: this.$form.createForm(this),
      state: {
        time: 60,
        loginBtn: false,
        // login type: 0 email, 1 username, 2 telephone
        loginType: 0,
        smsSendBtn: false
      },
      basicAuthEnabled: false,
      oauthEnabled: false
    }
  },

  created () {
    // Handle OAuth callback: backend redirects to /user/login#token=<jwt>
    // The token is in the fragment to avoid server-side logging.
    const hash = window.location.hash
    if (hash && hash.startsWith('#token=')) {
      const token = decodeURIComponent(hash.slice('#token='.length))
      // Clear the fragment from the URL without adding a history entry.
      window.history.replaceState(null, '', window.location.pathname + window.location.search)
      this.$store.dispatch('OAuthLoginSuccess', { token })
        .then(() => {
          this.$router.push({ name: 'dashboard' })
          this.$notification.success({
            message: 'Login successful!',
            description: 'Loading data..'
          })
        })
        .catch(err => this.requestFailed(err))
      return
    }

    // Fetch auth config to determine which login methods to display.
    this.$http.get('auth/config')
      .then(response => {
        this.basicAuthEnabled = response.body.basic_auth_enabled
        this.oauthEnabled = response.body.oauth_enabled
      })
      .catch(() => {
        // Fallback: show basic auth form if config endpoint is unavailable.
        this.basicAuthEnabled = true
      })
  },

  methods: {
    // handler
    handleUsernameOrEmail (rule, value, callback) {
      const { state } = this
      const regex = /^([a-zA-Z0-9_-])+@([a-zA-Z0-9_-])+((\.[a-zA-Z0-9_-]{2,3}){1,2})$/
      if (regex.test(value)) {
        state.loginType = 0
      } else {
        state.loginType = 1
      }
      callback()
    },
    handleTabClick (key) {
      this.customActiveKey = key
      // this.form.resetFields()
    },
    handleSubmit (e) {
      e.preventDefault()
      const {
        form: { validateFields },
        state,
        customActiveKey
      } = this

      state.loginBtn = true

      const validateFieldsKey = customActiveKey === 'tab1' ? ['username', 'password'] : ['mobile', 'captcha']

      validateFields(validateFieldsKey, { force: true }, (err, values) => {
        if (!err) {
          const loginParams = { ...values }

          loginParams.password = values.password
          loginParams.username = values.username

          this.$auth.login({
            body: loginParams,
            rememberMe: true,
            fetchUser: false,
            success (resp) {
              state.loginBtn = false
              this.loginSuccess(resp, loginParams)
            },
            error (resp) {
              this.$notification['error']({
                message: 'Authentifaction failed',
                description: resp.statusText,
                duration: 4
              })
              state.loginBtn = false
            }
          })
        } else {
          setTimeout(() => {
            state.loginBtn = false
          }, 600)
        }
      })
    },

    handleOAuthLogin () {
      window.location.href = `${window.location.protocol}//${window.location.host}/v1/auth/oauth/initiate`
    },

    loginSuccess (res, loginParams) {
      this.$store.dispatch('LoginSuccess', loginParams)
        .then((res) => {
          this.$router.push({ name: 'dashboard' })
          this.$notification.success({
            message: 'Login successful!',
            description: `Loading data..`
          })
        })
        .catch(err => this.requestFailed(err))
        .finally(() => {
        })
    },
    requestFailed (err) {
      console.log(err)
      this.$notification['error']({
        message: 'Request failed',
        description: ((err.response || {}).data || {}).message || 'Error while',
        duration: 4
      })
    }
  }
}
</script>

<style lang="less" scoped>
.user-layout-login {
  label {
    font-size: 14px;
  }

  .forge-password {
    font-size: 14px;
  }

  button.login-button {
    padding: 0 15px;
    font-size: 16px;
    height: 40px;
    width: 100%;
  }

  .user-login-other {
    text-align: left;
    margin-top: 24px;
    line-height: 22px;

    .item-icon {
      font-size: 24px;
      color: rgba(0, 0, 0, 0.2);
      margin-left: 16px;
      vertical-align: middle;
      cursor: pointer;
      transition: color 0.3s;

      &:hover {
        color: #1890ff;
      }
    }

    .register {
      float: right;
    }
  }
}

.oauth-section {
  margin-top: 16px;
}
</style>

