package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/supabase/auth/internal/conf"
	"golang.org/x/oauth2"
)

// Wechat

const IssuerWechat = "https://api.weixin.qq.com/sns/oauth2/access_token"

const WechatApiHost = "https://api.weixin.qq.com"

type WechatAccessToken struct {
	AccessToken  string `json:"access_token"`  // Interface call credentials
	ExpiresIn    int64  `json:"expires_in"`    // access_token interface call credential timeout time, unit (seconds)
	RefreshToken string `json:"refresh_token"` // User refresh access_token
	Openid       string `json:"openid"`        // Unique ID of authorized user
	Scope        string `json:"scope"`         // The scope of user authorization, separated by commas. (,)
	Unionid      string `json:"unionid"`       // This field will appear if and only if the website application has been authorized by the user's UserInfo.
}

var (
	WechatCacheMap map[string]WechatCacheMapValue
	Lock           sync.RWMutex
)

type WechatCacheMapValue struct {
	IsScanned     bool
	WechatUnionId string
}

type Config struct {
	AppID       string
	Secret      string
	Endpoint    oauth2.Endpoint
	RedirectURL string
	Scopes      []string
}

type WechatProvider struct {
	Client *http.Client
	*oauth2.Config
}

type WechatUser struct {
	Openid     string   `json:"openid"`   // The ID of an ordinary user, which is unique to the current developer account
	Nickname   string   `json:"nickname"` // Ordinary user nickname
	Sex        int      `json:"sex"`      // Ordinary user gender, 1 is male, 2 is female
	Language   string   `json:"language"`
	City       string   `json:"city"`       // City filled in by general user's personal data
	Province   string   `json:"province"`   // Province filled in by ordinary user's personal information
	Country    string   `json:"country"`    // Country, such as China is CN
	Headimgurl string   `json:"headimgurl"` // User avatar, the last value represents the size of the square avatar (there are optional values of 0, 46, 64, 96, 132, 0 represents a 640*640 square avatar), this item is empty when the user does not have an avatar
	Privilege  []string `json:"privilege"`  // User Privilege information, json array, such as Wechat Woka user (chinaunicom)
	Unionid    string   `json:"unionid"`    // Unified user identification. For an application under a Wechat open platform account, the unionid of the same user is unique.
}

func NewWechatProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {

	oauthScopes := []string{}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	return &WechatProvider{
		Client: &http.Client{Timeout: defaultTimeout},
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL: "https://open.weixin.qq.com/connect/qrconnect",
			},
			RedirectURL: ext.RedirectURI,
			Scopes:      oauthScopes,
		},
	}, nil
}

func (idp WechatProvider) AuthCodeURL(state string, args ...oauth2.AuthCodeOption) string {
	opts := make([]oauth2.AuthCodeOption, 0, 1)
	opts = append(opts, oauth2.SetAuthURLParam("appid", idp.Config.ClientID))
	authURL := idp.Config.AuthCodeURL(state, opts...)
	if authURL != "" {
		authURL = authURL + "#wechat_redirect"
	}
	return authURL
}

func (idp WechatProvider) GetOAuthToken(_ context.Context, code string, _ ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	if strings.HasPrefix(code, "wechat_oa:") {
		token := oauth2.Token{
			AccessToken: code,
			TokenType:   "WechatAccessToken",
			Expiry:      time.Time{},
		}
		return &token, nil
	}

	// Construct the request URL
	params := url.Values{}
	params.Add("grant_type", "authorization_code")
	params.Add("appid", idp.Config.ClientID)
	params.Add("secret", idp.Config.ClientSecret)
	params.Add("code", code)

	accessTokenUrl := fmt.Sprintf(IssuerWechat+"?%s", params.Encode())
	tokenResponse, err := idp.Client.Get(accessTokenUrl)
	if err != nil {
		return nil, err
	}
	defer func() {
		err := tokenResponse.Body.Close()
		if err != nil {
			log.Fatalf("Failed to close response body: %v", err)
			return
		}
	}()
	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(tokenResponse.Body)
	if err != nil {
		return nil, err
	}

	// Check if there is an error in the response
	if strings.Contains(buf.String(), "errcode") {
		return nil, fmt.Errorf(buf.String())
	}

	// Parse WechatAccessToken
	var wechatAccessToken WechatAccessToken
	if err = json.Unmarshal(buf.Bytes(), &wechatAccessToken); err != nil {
		return nil, err
	}

	// Convert WechatAccessToken to oauth2.Token
	token := oauth2.Token{
		AccessToken:  wechatAccessToken.AccessToken,
		TokenType:    "WechatAccessToken",
		RefreshToken: wechatAccessToken.RefreshToken,
		Expiry:       time.Now().Local().Add(time.Second * time.Duration(wechatAccessToken.ExpiresIn)),
	}

	// Add Openid to token extra
	raw := make(map[string]string)
	raw["Openid"] = wechatAccessToken.Openid
	token.WithExtra(raw)

	return &token, nil
}

func (idp WechatProvider) RequiresPKCE() bool {
	return false
}

func (idp WechatProvider) GetUserData(ctx context.Context, token *oauth2.Token) (*UserProvidedData, error) {
	var wechatUser WechatUser
	if strings.HasPrefix(token.AccessToken, "wechat_oa:") {
		Lock.RLock()
		mapValue, ok := WechatCacheMap[token.AccessToken[10:]]
		Lock.RUnlock()

		if !ok || mapValue.WechatUnionId == "" {
			return nil, fmt.Errorf("error ticket")
		}

		Lock.Lock()
		delete(WechatCacheMap, token.AccessToken[10:])
		Lock.Unlock()

		userInfo := UserProvidedData{
			Metadata: &Claims{
				Issuer:  IssuerWechat,
				Subject: mapValue.WechatUnionId,
			},
		}
		return &userInfo, nil
	}
	openid := token.Extra("Openid")

	userInfoUrl := fmt.Sprintf(WechatApiHost+"/sns/userinfo?access_token=%s&openid=%s", token.AccessToken, openid)
	resp, err := idp.Client.Get(userInfoUrl)
	if err != nil {
		return nil, fmt.Errorf("get user info error: %v", err)

	}
	defer func() {
		err := resp.Body.Close()
		if err != nil {
			log.Fatalf("Failed to close response body: %v", err)
			return
		}
	}()
	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(resp.Body)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(buf.Bytes(), &wechatUser); err != nil {
		return nil, err
	}

	id := wechatUser.Unionid
	if id == "" {
		id = wechatUser.Openid
	}
	userData := UserProvidedData{
		Metadata: &Claims{
			Issuer:   IssuerWechat,
			Subject:  id,
			NickName: wechatUser.Nickname,
			Name:     wechatUser.Nickname,
			Picture:  wechatUser.Headimgurl,
			Gender:   mapGender(wechatUser.Sex),

			// To be deprecated
			AvatarURL:  wechatUser.Headimgurl,
			FullName:   wechatUser.Nickname,
			ProviderId: id,
		},
	}
	return &userData, nil
}

func mapGender(sex int) string {
	switch sex {
	case 0:
		return "male"
	case 1:
		return "female"
	default:
		return "unknown"
	}
}
