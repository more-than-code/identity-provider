package repository

import (
	"context"
	"log"
	"mo-service-auth/mo-service-common/graph/model"
	"mo-service-auth/mo-service-common/util"
	"strings"

	"github.com/go-redis/redis/v9"
	"github.com/kelseyhightower/envconfig"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type CacheGetHandlerFunc func(ctx context.Context) interface{}
type CacheUpdateHandlerFunc func(ctx context.Context)
type CacheClearHandlerFunc func(ctx context.Context)

type Repository struct {
	mongoClient               *mongo.Client
	redisClient               *redis.Client
	votingCacheGetHandler     CacheGetHandlerFunc
	votingCacheUpdateHandler  CacheUpdateHandlerFunc
	votingCacheClearHandler   CacheClearHandlerFunc
	momentsCacheGetHandler    CacheGetHandlerFunc
	momentsCacheUpdateHandler CacheUpdateHandlerFunc
	momentsCacheClearHandler  CacheClearHandlerFunc
}

type Config struct {
	MongoUri string `envconfig:"MONGODB_URI"`
	RedisUri string `envconfig:"REDIS_URI"`
}

func NewRepository() (*Repository, error) {
	var cfg Config
	err := envconfig.Process("", &cfg)
	if err != nil {
		log.Fatal(err)
	}

	mongoClient, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(cfg.MongoUri))
	if err != nil {
		panic(err)
	}

	redisClient := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisUri,
		Password: "", // no password set
		DB:       0,  // use default DB
	})

	return &Repository{mongoClient: mongoClient, redisClient: redisClient}, nil
}

func (r *Repository) Disconnect() {
	if err := r.mongoClient.Disconnect(context.TODO()); err != nil {
		panic(err)
	}

	if err := r.redisClient.Close(); err != nil {
		panic(err)
	}
}

func (r *Repository) GetUserByPhoneOrEmail(input string) (*model.UserProfileWithPassword, error) {
	coll := r.mongoClient.Database("mohiguide").Collection("users")

	var filter bson.D
	if util.IsEmail(input) {
		filter = bson.D{{"email", strings.ToLower(input)}}
	} else {
		filter = bson.D{{"phone", input}}
	}

	user := &model.UserProfileWithPassword{}

	err := coll.FindOne(context.TODO(), filter).Decode(user)

	if err != nil {
		return nil, err
	}

	return user, nil
}
