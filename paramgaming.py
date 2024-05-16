import asyncio, sys, loguru
import re
from curl_cffi.requests import AsyncSession
from eth_account.messages import encode_defunct
from web3 import AsyncWeb3

logger = loguru.logger
logger.remove()
logger.add(sys.stdout, colorize=True, format="<g>{time:HH:mm:ss:SSS}</g> | <level>{message}</level>")


class tempmail:
    def __init__(self):
        self.url = 'https://www.1secmail.com/api/v1/'
        self.http = AsyncSession()
        self.login, self.domain, self.email = '', '', ''

    async def get_mail(self):
        for _ in range(5):
            try:
                res = await self.http.get(f'{self.url}?action=genRandomMailbox')
                if '@' in res.text:
                    self.email = res.json()[0]
                    self.login, self.domain = self.email.split('@')
                    return True
            except:
                pass
        return False

    async def get_code(self):
        for _ in range(20):
            try:
                res = await self.http.get(f'{self.url}?action=getMessages&login={self.login}&domain={self.domain}')
                if 'paramlabs' in res.text:
                    mailid = res.json()[0]['id']
                    res = await self.http.get(f'{self.url}?action=readMessage&id={mailid}&login={self.login}&domain={self.domain}')
                    allcode = re.findall(r'<p>(\d{6})<\\/p>', res.text)
                    if len(allcode) > 0:
                        return allcode[0]
            except:
                pass
            await asyncio.sleep(3)
        return None


class kopeechka:
    def __init__(self, token):
        self.token = token
        self.mailId, self.email = None, None
        self.http = AsyncSession()

    async def get_mail(self):
        params = {
            'api': '2.0',
            'site': 'paramlabs.io',
            'mail_type': 'mail.ru',
            'token': self.token,
            'soft': '99'
        }
        resp = await self.http.get('https://api.kopeechka.store/mailbox-get-email', params=params)
        if resp.status_code == 200 and resp.json()['status'] == 'OK':
            self.mailId = resp.json()['id']
            self.email = resp.json()['mail']
            return True
        elif 'ERROR' in resp.text:
            if resp.json()['value'] == 'BAD_BALANCE':
                logger.error('kopeechka余额不足')
        return False

    async def cancel_mail(self):
        params = {
            'id': self.mailId,
            'token': self.token,
            'api': '2.0'
        }
        resp = await self.http.get('https://api.kopeechka.store/mailbox-cancel', params=params)
        if resp.status_code == 200 and resp.json()['status'] == 'OK':
            return True

    async def get_code(self):
        params = {
            'full': '$FULL',
            'id': self.mailId,
            'token': self.token,
            'api': '2.0'
        }
        for _ in range(20):
            resp = await self.http.get(f"https://api.kopeechka.store/mailbox-get-message", params=params)
            if resp.status_code == 200 and resp.json()['status'] == 'OK':
                value = resp.json()['value']
                if value != 'WAIT_LINK':
                    allcode = re.findall(r'code=(\d{6})<', resp.json()['fullmessage'])
                    await self.cancel_mail()
                    return allcode[0]
            await asyncio.sleep(3)
        return None


class Twitter:
    def __init__(self, auth_token):
        self.auth_token = auth_token
        bearer_token = "Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"
        defaulf_headers = {
            "authority": "twitter.com",
            "origin": "https://twitter.com",
            "x-twitter-active-user": "yes",
            "x-twitter-client-language": "en",
            "authorization": bearer_token,
        }
        defaulf_cookies = {"auth_token": auth_token}
        self.Twitter = AsyncSession(headers=defaulf_headers, cookies=defaulf_cookies, timeout=120, impersonate="chrome120")
        self.authenticity_token, self.oauth_verifier = None, None

    async def get_twitter_token(self, oauth_token):
        try:
            response = await self.Twitter.get(f'https://api.twitter.com/oauth/authorize?oauth_token={oauth_token}')
            if 'authenticity_token' in response.text:
                self.authenticity_token = response.text.split('authenticity_token" value="')[1].split('"')[0]
                return True
            logger.error(f'获取authenticity_token失败')
            return False
        except Exception as e:
            logger.error(e)
            return False

    async def twitter_authorize(self, oauth_token):
        try:
            if not await self.get_twitter_token(oauth_token):
                return False
            data = {
                'authenticity_token': self.authenticity_token,
                'redirect_after_login': f'https://api.twitter.com/oauth/authorize?oauth_token={oauth_token}',
                'oauth_token': oauth_token
            }
            response = await self.Twitter.post('https://api.twitter.com/oauth/authorize', data=data)
            if 'oauth_verifier' in response.text:
                self.oauth_verifier = response.text.split('oauth_verifier=')[1].split('"')[0]
                return True
            return False
        except Exception as e:
            logger.error(e)
            return False


class PARAMG:
    def __init__(self, private_key, auth_token, kopee_token):
        self.w3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider('https://klaytn.api.onfinality.io/public'))
        self.client = AsyncSession(timeout=120, impersonate="chrome120")
        self.account = self.w3.eth.account.from_key(private_key)
        self.TM, self.TW = kopeechka(kopee_token), Twitter(auth_token)
        self.email = None

    async def signup(self):
        try:
            if not await self.TM.get_mail():
                return False
            self.email = self.TM.email
            json_data = {
                "email": self.email,
                "password": "hdd.cm_tw_0.2",
                "referCode": "3DE2AB4A57"
            }
            res = await self.client.post('https://paramgaming.com/api/v1/user/signup', json=json_data)
            if res.status_code == 200 and res.json()['status'] == 200:
                logger.info(f'{self.email} 发送验证码成功')
                return await self.verifyCode()
            else:
                logger.error(f'{self.email} 注册失败{res.json()["message"]}')
                return False
        except Exception as e:
            logger.error(f'{self.email} 注册异常：{e}')
            return False

    async def verifyCode(self):
        try:
            code = await self.TM.get_code()
            if code is None:
                return False
            json_data = {"email": self.email, "code": code}
            res = await self.client.post('https://paramgaming.com/api/v1/user/verifyCode', json=json_data)
            if res.status_code == 200 and res.json()['status'] == 200:
                logger.info(f'{self.email} 注册成功')
                return await self.login()
            else:
                logger.error(f'{self.email} 验证失败{res.json()["message"]}')
                return False
        except Exception as e:
            logger.error(f'{self.email} 验证异常：{e}')
            return False

    async def login(self):
        try:
            json_data = {
                "email": self.email,
                "password": "hdd.cm_tw_0.2"
            }
            res = await self.client.post('https://paramgaming.com/api/v1/user/login', json=json_data)
            if res.status_code == 200 and res.json()['status'] == 200:
                self.client.headers.update({'Authorization': res.json()['user']['token']})
                logger.info(f'{self.email} 登录成功')
                return await self.userPoints()
            else:
                logger.error(f'{self.email} 登录失败{res.json()["message"]}')
                return False
        except Exception as e:
            logger.error(f'{self.email} 登录异常：{e}')
            return False

    async def userPoints(self):
        try:
            res = await self.client.post('https://paramgaming.com/api/v1/user/userPoints')
            print(res.status_code, res.json())
            if res.status_code == 403 and res.json()['status'] == 403:
                await self.bindTwitter()
                return await self.userPoints()
            elif res.status_code == 200 and res.json()['status'] == 200:
                return await self.meGet()
            else:
                logger.error(f'{self.email} 获取积分失败{res.json()["message"]}')
                return False
        except Exception as e:
            logger.error(f'{self.email} 获取积分异常：{e}')
            return False

    async def meGet(self):
        try:
            res = await self.client.get('https://paramgaming.com/api/v1/trpc/me.get')
            print(res.text)
        except Exception as e:
            logger.error(f'{self.email} 获取个人信息异常：{e}')

    async def nonceGenerate(self):
        try:
            json_data = {"wallet": self.account.address}
            res = await self.client.post('https://paramgaming.com/api/v1/trpc/nonce.generate', json=json_data)
            if res.status_code == 200 and 'nonce' in res.text:
                nonce = res.json()['result']['data']['nonce']
                _id = res.json()['result']['data']['id']
                signature = self.account.sign_message(encode_defunct(text=nonce)).signature.hex()
                return await self.nonceValidate(_id, signature)
            else:
                logger.error(f'{self.email} nonce生成失败{res.json()["message"]}')
                return False
        except Exception as e:
            logger.error(f'{self.email} nonce生成异常：{e}')
            return False

    async def nonceValidate(self, _id, signature):
        try:
            json_data = {
                "id": _id,
                "signature": signature
            }
            res = await self.client.post('https://paramgaming.com/api/v1/trpc/nonce.validate', json=json_data)
            if res.status_code == 200 and res.json()['result']['data'] in res.text:
                logger.info(f'{self.email} 绑定钱包成功')
                return True
            else:
                logger.error(f'{self.email} 绑定钱包失败{res.json()["message"]}')
                return False
        except Exception as e:
            logger.error(f'{self.email} 绑定钱包异常：{e}')
            return False

    async def bindTwitter(self):
        try:
            res = await self.client.get('https://paramgaming.com/api/v1/user/auth/twitter', allow_redirects=False)
            if res.status_code == 302:
                location = res.headers['Location'] + '&'
                oauth_token = location.split('oauth_token=')[1].split('&')[0]
                return await self.callback(oauth_token)
        except Exception as e:
            logger.error(f'获取TwitterOauth异常：{e}')
            return False

    async def callback(self, oauth_token):
        try:
            if not await self.TW.twitter_authorize(oauth_token):
                return False
            params = {"oauth_token": oauth_token, "oauth_verifier": self.TW.oauth_verifier}
            res = await self.client.get('https://paramgaming.com/api/v1/user/auth/twitter/callback', params=params, allow_redirects=False)
            if res.status_code == 302:
                location = res.headers['location'] + '&'
                if 'tokensdata' in location:
                    tokensdata = location.split('tokensdata=')[1].split('&')[0]
                    tokenSecret = location.split('tokenSecret=')[1].split('&')[0]
                    username = location.split('username=')[1].split('&')[0]
                    return await self.connectTwitter(tokensdata, tokenSecret, username)
        except Exception as e:
            logger.error(f'callback异常：{e}')
            return False

    async def connectTwitter(self, tokensdata, tokenSecret, username):
        try:
            json_data = {
                "twitterUserName": username,
                "twitterToken": tokensdata,
                "twitterTokenSecret": tokenSecret,
                "twitterId": tokensdata.split('-')[0]
            }
            res = await self.client.post('https://paramgaming.com/api/v1/user/connectTwitter', json=json_data)
            if res.status_code == 200 and res.json()['status'] == 200:
                logger.info(f'{self.email} 绑定Twitter成功')
                return True
            else:
                logger.error(f'{self.email} 绑定Twitter失败{res.json()["message"]}')
                return False
        except Exception as e:
            logger.error(f'{self.email} 绑定Twitter异常：{e}')
            return False

    async def getUserTasks(self):
        try:
            res = await self.client.post('https://paramgaming.com/api/v1/user/getUserTasks')
            if res.status_code == 200 and res.json()['status'] == 200:
                for task in res.json()['result']['data']:
                    if not task['taskCompleted']:
                        await self.executeTask(task['taskId'], task['taskName'])
                    elif task['taskCompleted'] and not task['taskClaimed']:
                        await self.claimTaskRewards(task['taskId'], task['taskName'])

        except Exception as e:
            logger.error(f'{self.email} 获取任务异常：{e}')

    async def executeTask(self, task_id, task_name):
        try:
            json_data = {"taskId": task_id}
            res = await self.client.post('https://paramgaming.com/api/v1/user/executeTask', json=json_data)
            if res.status_code == 200 and res.json()['status'] == 200:
                logger.success(f'{self.email} 执行任务{task_name}成功')
                return await self.claimTaskRewards(task_id, task_name)
            return False
        except Exception as e:
            logger.error(f'{self.email} 执行任务{task_id}异常：{e}')
            return False

    async def claimTaskRewards(self, task_id, task_name):
        try:
            json_data = {"taskId": task_id}
            res = await self.client.post('https://paramgaming.com/api/v1/user/claimTaskRewards', json=json_data)
            if res.status_code == 200 and res.json()['status'] == 200:
                currentPointsTally = res.json()['data']['currentPointsTally']
                logger.success(f'{self.email} 领取任务{task_name}奖励成功, 当前积分：{currentPointsTally}')
                return True
            return False
        except Exception as e:
            logger.error(f'{self.email} 领取任务{task_id}奖励异常：{e}')
            return False


async def main():
    # https://kopeechka.store/?ref=28442  邮箱接码平台，老毛子的，mail.ru接码一次只要1卢布
    # auth_token 推特的auth_token，hdd.cm购买，0.2元一个
    paramg = PARAMG('私钥', 'auth_token', 'kopeechka_token')
    await paramg.signup()


if __name__ == '__main__':
    print('号多多 hdd.cm 推特低至0.2元一个')
    print('号多多 hdd.cm 推特低至0.2元一个')
    print('号多多 hdd.cm 推特低至0.2元一个')
    asyncio.run(main())
