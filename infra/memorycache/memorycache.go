package memorycache

import (
	"time"

	"github.com/patrickmn/go-cache"
)

type (
	cacheProvider interface {
		Set(key string, value interface{}, d time.Duration)
		Get(key string) (result interface{}, found bool)
	}

	//Client ...
	Client struct {
		cache cacheProvider
	}
)

//NewClient ...
func NewClient(expirationTime time.Duration, cleanUpInterval time.Duration) Client {
	return Client{
		cache: cache.New(expirationTime, cleanUpInterval),
	}
}

//Set adds the item in the cache and replace if it exists
func (c Client) Set(key string, value interface{}, expiration time.Duration) {
	c.cache.Set(key, value, expiration)
}

//Get gets an item with the specified key
func (c Client) Get(key string) (result interface{}, found bool) {
	return c.cache.Get(key)
}
