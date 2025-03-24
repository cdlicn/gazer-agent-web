package etcd

import (
	"context"
	"fmt"
	clientv3 "go.etcd.io/etcd/client/v3"
	"strings"
	"time"
)

var (
	client *clientv3.Client
)

func Init(address ...string) (err error) {
	client, err = clientv3.New(clientv3.Config{
		Endpoints:   address,
		DialTimeout: 3 * time.Second,
	})
	return
}

func List(ip string) (list map[string]string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	getResp, err := client.Get(ctx, ip, clientv3.WithPrefix())
	if err != nil {
		return nil, fmt.Errorf("failed to connect or access etcd: %v", err)
	}
	list = make(map[string]string)
	for _, kv := range getResp.Kvs {
		key := strings.Split(string(kv.Key), "\\")[1]
		val := string(kv.Value)
		list[key] = val
	}
	return
}

func Add(ip, topic, path string) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	getResp, err := client.Get(ctx, ip+"\\"+topic)
	if err != nil {
		return fmt.Errorf("failed to connect or access etcd: %v", err)
	}
	if len(getResp.Kvs) != 0 {
		return fmt.Errorf("this topic already exists.")
	}

	// 使用事务，将 ip\topic 和 add 键值对同时写入
	txn := client.Txn(ctx)
	_, err = txn.Then(
		clientv3.OpPut(ip+"\\"+topic, path),
		clientv3.OpPut("add", ip+"\\"+topic),
	).Commit()
	if err != nil {
		return fmt.Errorf("failed to connect or access etcd: %v", err)
	}
	return nil
}

func Update(ip, topic, path string) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	getResp, err := client.Get(ctx, ip+"\\"+topic)
	if err != nil {
		return fmt.Errorf("failed to connect or access etcd: %v", err)
	}
	if len(getResp.Kvs) == 0 {
		return fmt.Errorf("the topic does not exist.")
	}

	txn := client.Txn(ctx)
	_, err = txn.Then(
		clientv3.OpPut(ip+"\\"+topic, path),
		clientv3.OpPut("upd", ip+"\\"+topic),
	).Commit()
	if err != nil {
		return fmt.Errorf("failed to connect or access etcd: %v", err)
	}
	return nil
}

func Delete(ip, topic string) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	getResp, err := client.Get(ctx, ip+"\\"+topic)
	if err != nil {
		return fmt.Errorf("failed to connect or access etcd: %v", err)
	}
	if len(getResp.Kvs) == 0 {
		return fmt.Errorf("the topic does not exist.")
	}

	txn := client.Txn(ctx)
	_, err = txn.Then(
		clientv3.OpDelete(ip+"\\"+topic),
		clientv3.OpPut("del", ip+"\\"+topic),
	).Commit()
	if err != nil {
		return fmt.Errorf("failed to connect or access etcd: %v", err)
	}
	return nil
}

func Put(key, value string) (err error) {
	_, err = client.Put(context.Background(), key, value)
	return
}
